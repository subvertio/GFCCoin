"""
GFC Web Phone Verification - verify a phone number in a browser, for apps that can't run
Cloudflare Turnstile themselves (the Unreal phone app).

- POST /verify/link        (Bearer, post scope) -> {"verified": false, "url": ".../verify?c=<code>", "expires_in": 900}
                           or {"verified": true, "url": ""} when there's nothing to do
- GET  /verify?c=<code>    step 1: phone number + Turnstile
- POST /verify/web/start   form: c, phone, cf-turnstile-response -> step 2 (code sent), or step 1 with the error
- POST /verify/web/check   form: c, phone, code -> done (new-user grant, pending first post bonus) or step 2 again

With Firebase (GFC_FIREBASE_CONFIG set), step 1 and 2 are one page that texts and checks the code
with Firebase phone sign-in in the browser (Google's reCAPTCHA stands in for Turnstile):
- POST /verify/web/fb/start  form: c, phone -> JSON {"phone": "+1..."} once the limits allow it, or {"error"}
- POST /verify/web/fb/check  form: c, id_token (from Firebase) -> done, or step 1 with the error

The app opens the link in the system browser. The code in it stands in for the app's token on these
pages only: random, stored as a hash, one account, 15 minutes, gone once the account is verified.
The same limits apply as for /verify/phone/* (phone_verify.py). Without Firebase the pages run no
script of their own, only Turnstile's widget (which fills in cf-turnstile-response); with it, one
module script that talks to Firebase. They send no Referer, so the code never leaves the node.
"Back to GFC" opens gfc://verified, and the app refreshes the balance.

Environment: GFC_TURNSTILE_SITEKEY, the public site key paired with GFC_TURNSTILE_SECRET. The widget's
hostnames must include this node's domain. Or GFC_FIREBASE_CONFIG (phone_verify.py), with this node's
domain in the Firebase project's Authentication > Settings > Authorized domains.
"""
import datetime
import hashlib
import html
import json
import os
import secrets
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

import phone_verify
from app_share import _app_link, public_base_url
from app_verify import pay_on_verified
from config import DB_PATH
from security import Caller, caller_from_form

router = APIRouter()

LINK_TTL = datetime.timedelta(minutes=15)
TURNSTILE_SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js"
FIREBASE_SDK = "https://www.gstatic.com/firebasejs/10.12.2"


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _init(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS verify_links (
        code_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )''')


def create_link(username: str, db_path: str = DB_PATH) -> str:
    """A new link code for username; older ones stop working."""
    code = secrets.token_urlsafe(24)
    conn = sqlite3.connect(db_path)
    try:
        _init(conn)
        conn.execute("DELETE FROM verify_links WHERE username = ? OR expires_at < ?", (username, _now().isoformat()))
        conn.execute("INSERT INTO verify_links (code_hash, username, expires_at) VALUES (?, ?, ?)",
                     (_hash(code), username, (_now() + LINK_TTL).isoformat()))
        conn.commit()
    finally:
        conn.close()
    return code


def link_user(code: str, db_path: str = DB_PATH) -> Optional[str]:
    """The account a link code belongs to, or None if it's unknown or expired."""
    if not code or len(code) > 64:
        return None
    conn = sqlite3.connect(db_path)
    try:
        _init(conn)
        row = conn.execute("SELECT username FROM verify_links WHERE code_hash = ? AND expires_at > ?",
                           (_hash(code), _now().isoformat())).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


def _drop_links(username: str):
    conn = sqlite3.connect(DB_PATH)
    try:
        _init(conn)
        conn.execute("DELETE FROM verify_links WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()


def _is_verified(username: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    try:
        return phone_verify.is_verified(conn, username)
    finally:
        conn.close()


@router.post("/verify/link")
def verify_link(request: Request, caller: Caller = Depends(caller_from_form)):
    """A one-time link to verify the caller's phone in a browser."""
    username = caller.require("post")
    if _is_verified(username):
        return {"verified": True, "url": ""}
    code = create_link(username)
    return {"verified": False, "url": f"{_page_base(request)}/verify?c={code}",
            "expires_in": int(LINK_TTL.total_seconds())}


def _page_base(request: Request) -> str:
    """Where the app should open the page: the public domain, or this node itself when none is set (local nodes)."""
    if os.environ.get("GFC_PUBLIC_BASE_URL", "").strip():
        return public_base_url()
    return str(request.base_url).rstrip("/")


# ---------- pages ----------

def _page(request: Request, step: str, code: str = "", username: str = "", phone: str = "",
          error: str = "", paid: Optional[dict] = None) -> HTMLResponse:
    e = lambda s: html.escape(str(s), quote=True)  # noqa: E731
    nonce = secrets.token_urlsafe(16)
    sitekey = os.environ.get("GFC_TURNSTILE_SITEKEY", "").strip()
    needs_widget = bool(os.environ.get("GFC_TURNSTILE_SECRET", "").strip())
    widget, script = "", ""
    err = f'<p class="error">{e(error)}</p>' if error else ""
    who = f'<p class="who">Account: <b>@{e(username)}</b></p>' if username else ""
    back = _app_link("verified", f"{public_base_url()}/verify", request.headers.get("user-agent", ""))
    firebase = phone_verify.firebase_config() if step == "phone" else None

    if firebase:
        body, script = _firebase_phone_step(e, nonce, firebase, code, who, error, phone)
    elif step == "phone":
        if needs_widget and not sitekey:
            body = ("<h1>Verify your phone</h1><p>Phone verification isn't set up on this node yet. "
                    "Please try again later.</p>")
        else:
            if needs_widget:
                widget = f'<div class="cf-turnstile" data-sitekey="{e(sitekey)}" data-theme="dark"></div>'
                script = f'<script src="{TURNSTILE_SCRIPT}" async defer></script>'
            body = f"""<h1>Verify your phone</h1>
{who}<p>One account per phone number. Verifying unlocks the 100 GFC welcome grant, rewards for the
creators you watch, and your first post bonus if one is waiting.</p>
{err}<form method="post" action="/verify/web/start">
<input type="hidden" name="c" value="{e(code)}">
<label for="phone">Mobile number</label>
<input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="555 123 4567"
 value="{e(phone)}" required>
{widget}
<button type="submit">Text me a code</button>
</form>"""
    elif step == "code":
        body = f"""<h1>Enter the code</h1>
{who}<p>We texted a 6-digit code to <b>{e(phone)}</b>. It works for 10 minutes.</p>
{err}<form method="post" action="/verify/web/check">
<input type="hidden" name="c" value="{e(code)}">
<input type="hidden" name="phone" value="{e(phone)}">
<label for="code">Code</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*"
 maxlength="10" required autofocus>
<button type="submit">Verify</button>
</form>
<p class="small"><a href="/verify?c={e(code)}">Use a different number or send a new code</a></p>"""
    elif step == "done":
        lines = []
        if paid and paid.get("grant"):
            lines.append(f"+{paid['grant']:,.0f} GFC welcome grant")
        if paid and paid.get("first_post_bonus"):
            lines.append(f"+{paid['first_post_bonus']:,.0f} GFC first post bonus")
        earned = "".join(f'<p class="earned">{e(x)}</p>' for x in lines)
        note = "" if lines else "<p>Create a wallet in the app and your rewards will be paid there.</p>"
        body = f"""<h1>You're verified</h1>
{who}{earned}{note}
<p class="actions"><a href="{e(back)}">Back to GFC</a></p>"""
    elif step == "already":
        body = f"""<h1>Already verified</h1>{who}<p>This account's phone is verified. You're all set.</p>
<p class="actions"><a href="{e(back)}">Back to GFC</a></p>"""
    else:  # expired / unknown link
        body = """<h1>This link has expired</h1>
<p>Open GFC and tap <b>Verify phone</b> again for a fresh link.</p>"""

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Verify your phone | GFC</title>
{script}<style nonce="{nonce}">
[hidden]{{display:none!important}}
button:disabled{{opacity:.6}}
body{{margin:0;font-family:system-ui,sans-serif;background:#000;color:#e8e9f0}}
main{{max-width:440px;margin:0 auto;padding:40px 16px}}
h1{{font-size:1.5rem;margin:0 0 12px}}
p{{line-height:1.5;color:#b8bccc}}
.who b,.earned{{color:#fff}}
.earned{{font-size:1.3rem;font-weight:700;color:#ffc83d}}
.error{{padding:10px 12px;border-radius:8px;background:#3d1418;color:#ffb4b4}}
label{{display:block;margin:16px 0 6px;color:#b8bccc}}
input{{box-sizing:border-box;width:100%;padding:14px;border-radius:10px;border:1px solid #333;background:#0b0b0b;
color:#fff;font-size:1.1rem}}
input:focus{{outline:2px solid #3b4cca;border-color:#3b4cca}}
.cf-turnstile{{margin-top:16px;min-height:65px}}
button,.actions a{{display:block;box-sizing:border-box;width:100%;margin-top:20px;padding:14px;border:0;
border-radius:999px;background:#3b4cca;color:#fff;font-size:1.05rem;text-align:center;text-decoration:none}}
.small a{{color:#8f9cff}}
</style>
</head>
<body><main>
{body}
</main></body>
</html>
"""
    if firebase:
        # Firebase Auth and its invisible reCAPTCHA: Google's script, frame and API hosts. reCAPTCHA
        # styles its badge inline, so styles allow inline here (scripts still need the nonce).
        csp = (f"default-src 'none'; style-src 'unsafe-inline'; img-src https://www.gstatic.com data:; "
               f"script-src 'nonce-{nonce}' https://www.gstatic.com https://www.google.com https://apis.google.com; "
               f"frame-src https://www.google.com https://recaptcha.google.com https://{firebase['authDomain']}; "
               "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com "
               "https://www.google.com https://www.gstatic.com; "
               "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        page = page.replace(f'<style nonce="{nonce}">', "<style>", 1)
    else:
        csp = (f"default-src 'none'; style-src 'nonce-{nonce}'; script-src https://challenges.cloudflare.com; "
               "frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; "
               "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    return HTMLResponse(page, headers={
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",  # the link code is in the URL
        "Cache-Control": "no-store",
    })


def _firebase_phone_step(e, nonce: str, cfg: dict, code: str, who: str, error: str, phone: str):
    """Steps 1 and 2 in one page: the node checks the limits, Firebase texts and checks the code."""
    public = {k: cfg[k] for k in ("apiKey", "authDomain", "projectId", "appId") if cfg.get(k)}
    config_json = json.dumps(public).replace("</", "<\\/")
    body = f"""<div id="step-phone"><h1>Verify your phone</h1>
{who}<p>One account per phone number. Verifying unlocks the 100 GFC welcome grant, rewards for the
creators you watch, and your first post bonus if one is waiting.</p></div>
<div id="step-code" hidden><h1>Enter the code</h1>{who}
<p>We texted a 6-digit code to <b id="sent-to"></b>. It works for a few minutes.</p></div>
<p class="error" id="error"{"" if error else " hidden"}>{e(error)}</p>
<form id="phone-form">
<label for="phone">Mobile number</label>
<input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="555 123 4567"
 value="{e(phone)}" required>
<button type="submit" id="send">Text me a code</button>
</form>
<form id="code-form" hidden>
<label for="code">Code</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*"
 maxlength="10" required>
<button type="submit" id="verify">Verify</button>
<p class="small"><a href="#" id="again">Use a different number or send a new code</a></p>
</form>
<form id="done-form" method="post" action="/verify/web/fb/check" hidden>
<input type="hidden" name="c" id="c" value="{e(code)}">
<input type="hidden" name="id_token" id="id_token">
</form>
<div id="recaptcha"></div>
<noscript><p class="error">This page needs JavaScript to send the code.</p></noscript>"""
    script = f"""<script type="application/json" id="fb-config">{config_json}</script>
<script type="module" nonce="{nonce}">
import {{ initializeApp }} from "{FIREBASE_SDK}/firebase-app.js";
import {{ getAuth, setPersistence, inMemoryPersistence, RecaptchaVerifier, signInWithPhoneNumber, signOut }}
  from "{FIREBASE_SDK}/firebase-auth.js";
const $ = id => document.getElementById(id);
const auth = getAuth(initializeApp(JSON.parse($("fb-config").textContent)));
auth.useDeviceLanguage();
await setPersistence(auth, inMemoryPersistence);  // nothing kept in the browser afterwards
let confirmation = null, verifier = null;
const MESSAGES = {{
  "auth/invalid-verification-code": "That code isn't right. Check the text and try again.",
  "auth/code-expired": "That code expired. Send a new one.",
  "auth/invalid-phone-number": "That number doesn't look right. Check it and try again.",
  "auth/too-many-requests": "Too many attempts. Please try again later.",
  "auth/quota-exceeded": "We can't send more codes right now. Please try again later.",
  "auth/captcha-check-failed": "The security check didn't go through. Please try again.",
  "auth/network-request-failed": "Couldn't reach the verification service. Check your connection and try again.",
}};
function fail(msg) {{ $("error").textContent = msg || ""; $("error").hidden = !msg; }}
function step(name) {{
  for (const id of ["step-phone", "phone-form"]) $(id).hidden = name !== "phone";
  for (const id of ["step-code", "code-form"]) $(id).hidden = name !== "code";
}}
function freshVerifier() {{
  verifier?.clear();
  const box = document.createElement("div");
  $("recaptcha").replaceChildren(box);
  verifier = new RecaptchaVerifier(auth, box, {{ size: "invisible" }});
}}
$("phone-form").addEventListener("submit", async ev => {{
  ev.preventDefault(); fail(""); $("send").disabled = true;
  try {{
    const r = await fetch("/verify/web/fb/start", {{ method: "POST",
      body: new URLSearchParams({{ c: $("c").value, phone: $("phone").value }}) }});
    const j = await r.json().catch(() => ({{}}));
    if (j.reload) {{ location.reload(); return; }}
    if (!r.ok) {{ fail(j.error || "Something went wrong. Please try again."); return; }}
    freshVerifier();
    confirmation = await signInWithPhoneNumber(auth, j.phone, verifier);
    $("sent-to").textContent = j.phone; step("code"); $("code").focus();
  }} catch (err) {{
    console.warn("Firebase sign-in:", err?.code, err?.message);
    fail(MESSAGES[err?.code] || "We couldn't send the code right now. Please try again later.");
  }} finally {{ $("send").disabled = false; }}
}});
$("code-form").addEventListener("submit", async ev => {{
  ev.preventDefault(); fail(""); $("verify").disabled = true;
  try {{
    const result = await confirmation.confirm($("code").value.trim());
    $("id_token").value = await result.user.getIdToken();
    await signOut(auth);
    $("done-form").submit();
  }} catch (err) {{
    console.warn("Firebase confirm:", err?.code, err?.message);
    fail(MESSAGES[err?.code] || "That code didn't work. Please try again.");
    $("verify").disabled = false;
  }}
}});
$("again").addEventListener("click", ev => {{ ev.preventDefault(); fail(""); $("code").value = ""; step("phone"); }});
</script>"""
    return body, script


@router.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request, c: str = ""):
    username = link_user(c)
    if not username:
        return _page(request, "expired")
    if _is_verified(username):
        return _page(request, "already", username=username)
    return _page(request, "phone", code=c, username=username)


@router.post("/verify/web/start", response_class=HTMLResponse)
def verify_web_start(request: Request, c: str = Form(""), phone: str = Form(""),
                     turnstile: str = Form("", alias="cf-turnstile-response")):
    username = link_user(c)
    if not username:
        return _page(request, "expired")
    try:
        phone_verify.check_turnstile(turnstile, request.client.host if request.client else "")
        phone_verify.start_verification(DB_PATH, username, phone)
    except phone_verify.FlowError as ex:
        if ex.status == 409 and _is_verified(username):
            return _page(request, "already", username=username)
        return _page(request, "phone", code=c, username=username, phone=phone, error=_friendly(ex))
    return _page(request, "code", code=c, username=username, phone=phone.strip())


@router.post("/verify/web/check", response_class=HTMLResponse)
def verify_web_check(request: Request, c: str = Form(""), phone: str = Form(""), code: str = Form("")):
    username = link_user(c)
    if not username:
        return _page(request, "expired")
    try:
        result = phone_verify.check_verification(DB_PATH, username, phone, code)
    except phone_verify.FlowError as ex:
        step = "phone" if ex.status == 400 and "expired" in ex.detail else "code"
        return _page(request, step, code=c, username=username, phone=phone, error=_friendly(ex))
    if not result.get("verified"):
        return _page(request, "code", code=c, username=username, phone=phone,
                     error="That code isn't right. Check the text and try again.")
    paid = pay_on_verified(username)
    _drop_links(username)
    return _page(request, "done", username=username, paid=paid)


@router.post("/verify/web/fb/start")
def verify_web_fb_start(c: str = Form(""), phone: str = Form("")):
    """Firebase step 1: the same checks and limits as an SMS start; the browser then texts the code."""
    username = link_user(c)
    if not username or not phone_verify.firebase_config():
        return JSONResponse({"reload": True}, status_code=410)  # the page shows why when it reloads
    try:
        started = phone_verify.start_verification(DB_PATH, username, phone, send=False)
    except phone_verify.FlowError as ex:
        if ex.status == 409 and _is_verified(username):
            return JSONResponse({"reload": True}, status_code=409)
        return JSONResponse({"error": _friendly(ex)}, status_code=ex.status)
    return {"phone": started["phone"]}


@router.post("/verify/web/fb/check", response_class=HTMLResponse)
def verify_web_fb_check(request: Request, c: str = Form(""), id_token: str = Form("")):
    """Firebase step 2: the ID token Firebase gave the browser proves the number."""
    username = link_user(c)
    if not username:
        return _page(request, "expired")
    try:
        phone_verify.complete_firebase_verification(DB_PATH, username, id_token)
    except phone_verify.FlowError as ex:
        if ex.status == 409 and _is_verified(username):
            return _page(request, "already", username=username)
        return _page(request, "phone", code=c, username=username, error=_friendly(ex))
    paid = pay_on_verified(username)
    _drop_links(username)
    return _page(request, "done", username=username, paid=paid)


_TURNSTILE_MESSAGES = {
    phone_verify.TURNSTILE_EXPIRED: "The check above expired. Wait for it to show Success again, then try again.",
    phone_verify.TURNSTILE_REJECTED: "The check above didn't go through. Please try again.",
    phone_verify.TURNSTILE_MISCONFIGURED: "Phone verification isn't working on this node right now. "
                                          "Please try again later.",
    phone_verify.TURNSTILE_UNAVAILABLE: "Couldn't reach the bot check. Please try again in a minute.",
}


_NODE_PROBLEM = "Phone verification isn't working on this node right now. Please try again later."

# Twilio error codes (https://www.twilio.com/docs/api/errors) -> what the person can do about it
_PROVIDER_MESSAGES = {
    60200: "That number can't receive texts. Check it and try again.",
    21211: "That number can't receive texts. Check it and try again.",
    60205: "That looks like a landline. Please use a mobile number.",
    60203: "Too many codes were sent to this number. Wait 10 minutes, then try again.",
    60410: "Our SMS provider is blocking texts to this number for now. Please try again later, or use another number.",
    60605: "We can't text numbers in that country yet.",
    # The operator's problem (trial account, bad key, missing permission, wrong service): not the person's
    21608: _NODE_PROBLEM,
    20003: _NODE_PROBLEM,
    20404: _NODE_PROBLEM,
    8021: _NODE_PROBLEM,
}


def _friendly(ex: phone_verify.FlowError) -> str:
    detail = ex.detail or "Something went wrong."
    if ex.status == 403:
        return _TURNSTILE_MESSAGES.get(ex.reason, "Please complete the check above, then try again.")
    if ex.reason.startswith(phone_verify.PROVIDER_REASON) and "VoIP" not in detail:
        code = ex.reason.partition(":")[2]
        return _PROVIDER_MESSAGES.get(int(code) if code else None,
                                      "We couldn't send the code right now. Please try again later.")
    if ex.status == 429:
        return "Too many attempts today. Please try again tomorrow."
    return detail[0].upper() + detail[1:] + ("" if detail.endswith(".") else ".")
