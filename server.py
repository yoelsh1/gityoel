"""שרת MCP ל-hamashv — חושף כלים לכל הפרויקטים תחת /root/workspace.

בלמי בטיחות:
1. טוקן חובה (Authorization: Bearer <MCP_AUTH_TOKEN>) — או access token שהונפק דרך OAuth — על כל בקשה ל-/mcp.
2. לוג append-only של כל קריאת-כלי, לפני הביצוע.

תמיכת OAuth 2.0 (RFC 7591/8414/9728 + PKCE) נוספה כדי לאפשר חיבור connector של claude.ai,
לצד הטוקן הסטטי הקיים (טלגרם/שימוש ישיר ממשיכים לעבוד בלי שינוי).
"""
import base64
import datetime
import hashlib
import html
import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path

import psycopg2
from dotenv import load_dotenv
from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

WORKSPACE_ROOT = Path("/root/workspace")
LOG_PATH = BASE_DIR / "logs" / "tools.log"
AUTH_TOKEN = os.environ["MCP_AUTH_TOKEN"]
PORT = int(os.environ.get("MCP_PORT", "8020"))
ISSUER = "https://mcp.yoelsh.com"

DSNS = {
    "ai-hub": os.environ["DSN_AI_HUB"],
    "equator": os.environ["DSN_EQUATOR"],
    "whats": os.environ["DSN_WHATS"],
}


def log_call(tool: str, args: dict) -> None:
    """כותב שורת לוג (timestamp + שם כלי + ארגומנטים מקוצרים) לפני ביצוע הכלי."""
    short_args = {
        k: (v if len(str(v)) <= 200 else str(v)[:200] + "…") for k, v in args.items()
    }
    line = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "tool": tool,
        "args": short_args,
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")


def normalize_path(path: str) -> Path:
    """מנרמל נתיב (מקזז .. וכו'), נתיב יחסי נפתר מול /root/workspace."""
    p = Path(path)
    if not p.is_absolute():
        p = WORKSPACE_ROOT / p
    return Path(os.path.normpath(str(p)))


mcp = FastMCP("hamashv-mcp")


@mcp.tool
def read_file(path: str) -> str:
    """קריאת תוכן קובץ."""
    log_call("read_file", {"path": path})
    return normalize_path(path).read_text(encoding="utf-8", errors="replace")


@mcp.tool
def write_file(path: str, content: str) -> str:
    """כתיבה/יצירה של קובץ. אם הקובץ קיים — גיבוי .bak לפני דריסה."""
    log_call("write_file", {"path": path, "content_len": len(content)})
    real_path = normalize_path(path)
    if real_path.exists():
        backup = real_path.with_name(real_path.name + ".bak")
        backup.write_bytes(real_path.read_bytes())
    real_path.parent.mkdir(parents=True, exist_ok=True)
    real_path.write_text(content, encoding="utf-8")
    return f"נכתב: {real_path}"


@mcp.tool
def list_dir(path: str = "/root/workspace") -> list[str]:
    """רשימת קבצים ותיקיות בנתיב נתון."""
    log_call("list_dir", {"path": path})
    return sorted(os.listdir(normalize_path(path)))


@mcp.tool
def run_shell(command: str, cwd: str | None = None) -> dict:
    """הרצת פקודת shell. מחזיר stdout, stderr וקוד יציאה. כל הרצה נרשמת ללוג לפני הביצוע."""
    real_cwd = normalize_path(cwd) if cwd else WORKSPACE_ROOT
    log_call("run_shell", {"command": command, "cwd": str(real_cwd)})
    result = subprocess.run(
        command,
        shell=True,
        cwd=real_cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


@mcp.tool
def query_db(project: str, sql: str) -> dict:
    """הרצת SQL על אחד ממסדי הנתונים (ai-hub / equator / whats).

    ברירת מחדל: read-only (SELECT). כתיבה (כל שאילתה שאינה SELECT) נרשמת
    ללוג בנפרד ומפורשות לפני הביצוע.
    """
    if project not in DSNS:
        raise ValueError(f"project לא מוכר: {project}. אפשרויות: {list(DSNS)}")
    is_write = not sql.strip().upper().startswith("SELECT")
    log_call("query_db", {"project": project, "sql": sql, "write": is_write})
    if is_write:
        log_call("query_db:WRITE", {"project": project, "sql": sql})
    conn = psycopg2.connect(DSNS[project])
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            if is_write:
                conn.commit()
                return {"rowcount": cur.rowcount}
            columns = [d.name for d in cur.description] if cur.description else []
            rows = cur.fetchall()
            return {"columns": columns, "rows": rows}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# OAuth 2.0 (עבור connector של claude.ai) — אחסון קובץ פשוט, טוקנים אטומים
# ---------------------------------------------------------------------------

OAUTH_STORE_PATH = BASE_DIR / "oauth_store.json"
_store_lock = threading.Lock()

PUBLIC_PATHS = {
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/register",
    "/authorize",
    "/token",
}


def _empty_store() -> dict:
    return {"clients": {}, "codes": {}, "tokens": {}, "refresh_tokens": {}}


def load_store() -> dict:
    if not OAUTH_STORE_PATH.exists():
        return _empty_store()
    with open(OAUTH_STORE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_store(store: dict) -> None:
    OAUTH_STORE_PATH.write_text(
        json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    os.chmod(OAUTH_STORE_PATH, 0o600)


def verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return computed == challenge


def issue_tokens(client_id: str) -> dict:
    now = time.time()
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)
    with _store_lock:
        store = load_store()
        store["tokens"][access_token] = {"client_id": client_id, "expires": now + 3600}
        store["refresh_tokens"][refresh_token] = {
            "client_id": client_id,
            "expires": now + 90 * 86400,
        }
        save_store(store)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token,
    }


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_as_metadata(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "registration_endpoint": f"{ISSUER}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }
    )


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_resource_metadata(request: Request) -> JSONResponse:
    return JSONResponse({"resource": f"{ISSUER}/mcp", "authorization_servers": [ISSUER]})


@mcp.custom_route("/register", methods=["POST"])
async def oauth_register(request: Request) -> JSONResponse:
    """Dynamic Client Registration (RFC 7591) — לקוח ציבורי, בלי סוד, PKCE חובה."""
    body = await request.json()
    redirect_uris = body.get("redirect_uris") or []
    if not redirect_uris:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    client_id = secrets.token_urlsafe(16)
    client_name = body.get("client_name", "")
    with _store_lock:
        store = load_store()
        store["clients"][client_id] = {
            "redirect_uris": redirect_uris,
            "client_name": client_name,
        }
        save_store(store)
    log_call("oauth_register", {"client_id": client_id, "client_name": client_name})
    return JSONResponse(
        {
            "client_id": client_id,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": client_name,
        },
        status_code=201,
    )


def _consent_html(params: dict, error: str = "") -> str:
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v or "")}">'
        for k, v in params.items()
    )
    error_html = f'<p style="color:#c00">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="he" dir="rtl"><head><meta charset="utf-8">
<title>אישור גישה — hamashv MCP</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:60px auto">
<h2>אישור גישה ל-MCP</h2>
<p>מבקש/ת גישה לכלים על השרת. הזן/י את הטוקן הקיים לאישור החיבור.</p>
{error_html}
<form method="POST" action="/authorize">
{hidden}
<input type="text" name="token" placeholder="טוקן" autocomplete="off" spellcheck="false"
       style="width:100%;padding:8px;box-sizing:border-box;font-family:monospace;direction:ltr" required autofocus>
<button type="submit" style="margin-top:12px;padding:8px 16px">אשר גישה</button>
</form>
</body></html>"""


@mcp.custom_route("/authorize", methods=["GET"])
async def oauth_authorize_get(request: Request) -> HTMLResponse:
    q = dict(request.query_params)
    params = {
        "client_id": q.get("client_id", ""),
        "redirect_uri": q.get("redirect_uri", ""),
        "state": q.get("state", ""),
        "code_challenge": q.get("code_challenge", ""),
        "code_challenge_method": q.get("code_challenge_method", "S256"),
        "scope": q.get("scope", ""),
    }
    return HTMLResponse(_consent_html(params))


@mcp.custom_route("/authorize", methods=["POST"])
async def oauth_authorize_post(request: Request) -> Response:
    form = await request.form()
    params = {
        k: form.get(k, "")
        for k in ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope"]
    }
    token = form.get("token", "").strip()

    store = load_store()
    client = store["clients"].get(params["client_id"])
    if not client or params["redirect_uri"] not in client["redirect_uris"]:
        log_call("oauth_authorize:REJECT", {"reason": "unknown client/redirect_uri", **params})
        return HTMLResponse(_consent_html(params, "client_id / redirect_uri לא תואמים לרישום"), status_code=400)

    if token != AUTH_TOKEN:
        log_call("oauth_authorize:REJECT", {"reason": "bad token", "client_id": params["client_id"]})
        return HTMLResponse(_consent_html(params, "טוקן שגוי"), status_code=401)

    code = secrets.token_urlsafe(32)
    with _store_lock:
        store = load_store()
        store["codes"][code] = {
            "client_id": params["client_id"],
            "redirect_uri": params["redirect_uri"],
            "code_challenge": params["code_challenge"],
            "code_challenge_method": params["code_challenge_method"] or "S256",
            "expires": time.time() + 600,
            "used": False,
        }
        save_store(store)

    log_call("oauth_authorize:APPROVE", {"client_id": params["client_id"]})
    redirect_to = f"{params['redirect_uri']}?code={code}"
    if params["state"]:
        redirect_to += f"&state={params['state']}"
    return RedirectResponse(redirect_to, status_code=302)


@mcp.custom_route("/token", methods=["POST"])
async def oauth_token(request: Request) -> JSONResponse:
    form = await request.form()
    grant_type = form.get("grant_type")
    log_call("oauth_token", {"grant_type": grant_type})

    if grant_type == "authorization_code":
        code = form.get("code", "")
        verifier = form.get("code_verifier", "")
        redirect_uri = form.get("redirect_uri", "")
        with _store_lock:
            store = load_store()
            entry = store["codes"].get(code)
            if not entry or entry["used"] or entry["expires"] < time.time():
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if entry["redirect_uri"] != redirect_uri:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if not verify_pkce(verifier, entry["code_challenge"]):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            entry["used"] = True
            save_store(store)
        return JSONResponse(issue_tokens(entry["client_id"]))

    if grant_type == "refresh_token":
        refresh_token = form.get("refresh_token", "")
        store = load_store()
        entry = store["refresh_tokens"].get(refresh_token)
        if not entry or entry["expires"] < time.time():
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return JSONResponse(issue_tokens(entry["client_id"]))

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


class AuthMiddleware(BaseHTTPMiddleware):
    """בודק Bearer token על כל בקשה ל-/mcp: טוקן סטטי (MCP_AUTH_TOKEN) או access token מ-OAuth.
    נתיבי ה-OAuth (well-known/register/authorize/token) פתוחים ללא אימות Bearer — כל אחד מהם
    מאמת בעצמו (למשל /authorize דורש את הטוקן בטופס ההסכמה).
    """

    async def dispatch(self, request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        header = request.headers.get("authorization", "")
        token = header[7:] if header.lower().startswith("bearer ") else header

        if token == AUTH_TOKEN:
            return await call_next(request)

        store = load_store()
        entry = store["tokens"].get(token)
        if entry and entry["expires"] >= time.time():
            return await call_next(request)

        return JSONResponse(
            {"error": "unauthorized"},
            status_code=401,
            headers={
                "WWW-Authenticate": f'Bearer resource_metadata="{ISSUER}/.well-known/oauth-protected-resource"'
            },
        )


if __name__ == "__main__":
    mcp.run(
        transport="http",
        host="127.0.0.1",
        port=PORT,
        path="/mcp",
        middleware=[Middleware(AuthMiddleware)],
    )
