"""
GFC Account Recovery pages and API (logic in account_recovery.py).

Pages (Firebase's web SDK sends the SMS code or the email sign-in link; it only runs in pages):
- GET  /reset                 forgot password: username + the account's phone or email
- GET  /reset/email?f=        where the emailed sign-in link lands
- POST /reset/start           form: username, method, phone|email -> JSON {flow, phone|email} or {error}
- POST /reset/prove           form: f, id_token -> the new-password step
- POST /reset/complete        form: f, password, password2, recovery_code, accept_locked -> done,
                              with the new recovery code
- GET  /reset/set?f=          an operator's reset link (account_recovery.py reset-link): straight
                              to the new-password step
- GET  /account/phone         changed your number: username + the account's verified email,
                              then the new number (/account/phone/email, /start, /prove, /new, /prove-new)
- GET  /account/email?f=      verify an email (link from POST /email/link), then /account/email/done

API (Bearer):
- POST /email/link                  {"url"} to verify an email in the browser
- POST /account/recovery-code       form: password -> {"recovery_code"} (replaces the old one)
- GET  /account/security            {"recovery_code": bool, "email_verified", "email" (masked), "phone_verified"}

Flow codes in URLs are one-time, bound to one account, and expire (account_recovery.py); pages
send no Referer. Environment: GFC_FIREBASE_CONFIG (phone_verify.py), with Email link sign-in
enabled in the Firebase project (Authentication > Sign-in method > Email/Password > Email link).
"""
import html
import json
import secrets
import sqlite3

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

import account_recovery as recovery
import keystore
import phone_verify
from account_recovery import RecoveryError
from app_share import _app_link, public_base_url
from app_webverify import FIREBASE_SDK, _page_base
from config import DB_PATH
from security import Caller, caller_from_form, caller_from_query, verify_password

router = APIRouter()
e = lambda s: html.escape(str(s), quote=True)  # noqa: E731

# One module script for every step: the page's #cfg says which endpoints to call.
_SCRIPT = """
import { initializeApp } from "__SDK__/firebase-app.js";
import { getAuth, setPersistence, inMemoryPersistence, RecaptchaVerifier, signInWithPhoneNumber,
  sendSignInLinkToEmail, isSignInWithEmailLink, signInWithEmailLink, signOut } from "__SDK__/firebase-auth.js";
const $ = id => document.getElementById(id);
const cfg = JSON.parse($("cfg").textContent);
const auth = getAuth(initializeApp(cfg.firebase));
auth.useDeviceLanguage();
await setPersistence(auth, inMemoryPersistence);
let confirmation = null, verifier = null, flow = cfg.flow || "";
const MESSAGES = {
  "auth/invalid-verification-code": "That code isn't right. Check the text and try again.",
  "auth/code-expired": "That code expired. Send a new one.",
  "auth/invalid-phone-number": "That number doesn't look right.",
  "auth/invalid-email": "That email address doesn't look right.",
  "auth/invalid-action-code": "That link has expired or was already used. Please start again.",
  "auth/expired-action-code": "That link has expired. Please start again.",
  "auth/too-many-requests": "Too many attempts. Please try again later.",
  "auth/quota-exceeded": "We can't send more right now. Please try again later.",
  "auth/operation-not-allowed": "Email sign-in isn't switched on for this node yet.",
  "auth/network-request-failed": "Couldn't reach the sign-in service. Check your connection.",
};
function fail(msg) { $("error").textContent = msg || ""; $("error").hidden = !msg; }
function show(name) { for (const s of document.querySelectorAll("section")) s.hidden = s.id !== "s-" + name; }
function freshVerifier() {
  verifier?.clear();
  const box = document.createElement("div");
  $("recaptcha").replaceChildren(box);
  verifier = new RecaptchaVerifier(auth, box, { size: "invisible" });
}
async function finish(user) {
  $("id_token").value = await user.getIdToken();
  $("f").value = flow;
  await signOut(auth);
  $("done-form").submit();
}
for (const r of document.querySelectorAll("input[name=method]")) r.addEventListener("change", () => {
  for (const m of ["phone", "email"]) $("by-" + m).hidden = $("method-" + m) && !$("method-" + m).checked;
});
$("start-form")?.addEventListener("submit", async ev => {
  ev.preventDefault(); fail(""); const button = ev.submitter; if (button) button.disabled = true;
  try {
    const body = new URLSearchParams(new FormData($("start-form")));
    if (flow) body.set("f", flow);
    const r = await fetch(cfg.start, { method: "POST", body });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { fail(j.error || "Something went wrong. Please try again."); return; }
    if (j.flow) flow = j.flow;
    if (j.phone) {
      freshVerifier();
      confirmation = await signInWithPhoneNumber(auth, j.phone, verifier);
      $("sent-to").textContent = j.phone; show("code"); $("code").focus();
    } else if (j.email) {
      await sendSignInLinkToEmail(auth, j.email,
        { url: location.origin + cfg.landing + "?f=" + encodeURIComponent(flow), handleCodeInApp: true });
      try { localStorage.setItem("gfcEmailForLink", j.email); } catch {}
      $("sent-email").textContent = j.email; show("sent");
    }
  } catch (err) {
    console.warn("Firebase:", err?.code, err?.message);
    fail(MESSAGES[err?.code] || "We couldn't send it right now. Please try again later.");
  } finally { if (button) button.disabled = false; }
});
$("code-form")?.addEventListener("submit", async ev => {
  ev.preventDefault(); fail(""); $("verify").disabled = true;
  try { await finish((await confirmation.confirm($("code").value.trim())).user); }
  catch (err) { fail(MESSAGES[err?.code] || "That code didn't work. Please try again."); $("verify").disabled = false; }
});
async function completeEmail(email) {
  try {
    const cred = await signInWithEmailLink(auth, email, location.href);
    try { localStorage.removeItem("gfcEmailForLink"); } catch {}
    await finish(cred.user);
  } catch (err) {
    console.warn("Firebase:", err?.code, err?.message);
    show("ask"); fail(MESSAGES[err?.code] || "That sign-in link didn't work. Please start again.");
  }
}
if (cfg.mode === "landing") {
  if (!isSignInWithEmailLink(auth, location.href)) { show("ask"); fail("Open this page from the link in the email."); }
  else {
    let saved = null; try { saved = localStorage.getItem("gfcEmailForLink"); } catch {}
    if (saved) completeEmail(saved); else show("ask");
    $("ask-form").addEventListener("submit", ev => { ev.preventDefault(); fail(""); completeEmail($("ask-email").value.trim()); });
  }
}
"""


def _page(title: str, body: str, cfg: dict = None) -> HTMLResponse:
    """A page; with cfg, the Firebase script and the CSP it needs."""
    nonce = secrets.token_urlsafe(16)
    firebase = phone_verify.firebase_config() if cfg is not None else None
    script = ""
    if cfg is not None and firebase:
        cfg = {**cfg, "firebase": {k: firebase[k] for k in ("apiKey", "authDomain", "projectId", "appId") if firebase.get(k)}}
        cfg_json = json.dumps(cfg).replace("</", "<\\/")
        module = _SCRIPT.replace("__SDK__", FIREBASE_SDK)
        script = (f'<script type="application/json" id="cfg">{cfg_json}</script>\n'
                  f'<script type="module" nonce="{nonce}">{module}</script>')
    elif cfg is not None:
        body = (f"<h1>{e(title)}</h1><p>Account recovery isn't set up on this node yet. "
                "Please try again later.</p>")
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{e(title)} | GFC</title>
{script}<style{'' if script else f' nonce="{nonce}"'}>
[hidden]{{display:none!important}}
button:disabled{{opacity:.6}}
body{{margin:0;font-family:system-ui,sans-serif;background:#000;color:#e8e9f0}}
main{{max-width:440px;margin:0 auto;padding:40px 16px}}
h1{{font-size:1.5rem;margin:0 0 12px}}
p,li{{line-height:1.5;color:#b8bccc}}
b{{color:#fff}}
.error{{padding:10px 12px;border-radius:8px;background:#3d1418;color:#ffb4b4}}
.warn{{padding:10px 12px;border-radius:8px;background:#2b2410;color:#ffd98a}}
label{{display:block;margin:16px 0 6px;color:#b8bccc}}
label.inline{{display:flex;gap:8px;align-items:flex-start;margin:12px 0}}
input[type=text],input[type=tel],input[type=email],input[type=password]{{box-sizing:border-box;width:100%;padding:14px;
border-radius:10px;border:1px solid #333;background:#0b0b0b;color:#fff;font-size:1.1rem}}
input:focus{{outline:2px solid #3b4cca;border-color:#3b4cca}}
.choice{{display:flex;gap:16px;margin-top:8px}}
button,.actions a{{display:block;box-sizing:border-box;width:100%;margin-top:20px;padding:14px;border:0;
border-radius:999px;background:#3b4cca;color:#fff;font-size:1.05rem;text-align:center;text-decoration:none}}
.code{{margin:16px 0;padding:16px;border-radius:12px;background:#10142e;border:1px solid #3b4cca;color:#fff;
font:600 1.2rem ui-monospace,monospace;letter-spacing:.04em;text-align:center;word-break:break-all}}
.small,.small a{{color:#8f9cff;font-size:.95rem}}
</style>
</head>
<body><main>
{body}
</main></body>
</html>
"""
    if script:
        # Firebase Auth and its invisible reCAPTCHA (styles inline; scripts still need the nonce).
        csp = (f"default-src 'none'; style-src 'unsafe-inline'; img-src https://www.gstatic.com data:; "
               f"script-src 'nonce-{nonce}' https://www.gstatic.com https://www.google.com https://apis.google.com; "
               f"frame-src https://www.google.com https://recaptcha.google.com https://{firebase['authDomain']}; "
               "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com "
               "https://www.google.com https://www.gstatic.com; "
               "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
    else:
        csp = f"default-src 'none'; style-src 'nonce-{nonce}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    return HTMLResponse(page, headers={"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
                                       "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})


def _proof_sections(prove_action: str, intro_code: str = "We texted a 6-digit code to") -> str:
    """The code step, the check-your-email step, the email question for links opened elsewhere,
    and the hidden form that posts Firebase's result to the node."""
    return f"""<section id="s-code" hidden><h1>Enter the code</h1>
<p>{intro_code} <b id="sent-to"></b>. It works for a few minutes.</p>
<form id="code-form"><label for="code">Code</label>
<input id="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="10" required>
<button type="submit" id="verify">Continue</button></form></section>
<section id="s-sent" hidden><h1>Check your email</h1>
<p>We sent a sign-in link to <b id="sent-email"></b>. Open it on this phone to continue. It works for
about half an hour.</p></section>
<section id="s-ask" hidden><h1>Confirm your email</h1>
<form id="ask-form"><label for="ask-email">The email the link was sent to</label>
<input id="ask-email" type="email" autocomplete="email" required><button type="submit">Continue</button></form></section>
<form id="done-form" method="post" action="{e(prove_action)}" hidden>
<input type="hidden" name="f" id="f"><input type="hidden" name="id_token" id="id_token"></form>
<div id="recaptcha"></div>
<noscript><p class="error">This page needs JavaScript.</p></noscript>"""


def _error_p(msg: str = "") -> str:
    return f'<p class="error" id="error"{"" if msg else " hidden"}>{e(msg)}</p>'


def _back(request: Request) -> str:
    link = _app_link("feed", f"{public_base_url()}/web", request.headers.get("user-agent", ""))
    return f'<p class="actions"><a href="{e(link)}">Back to GFC</a></p>'


def _expired(title: str, msg: str, start_url: str) -> HTMLResponse:
    return _page(title, f'<h1>{e(title)}</h1><p class="error">{e(msg)}</p>'
                        f'<p class="actions"><a href="{e(start_url)}">Start again</a></p>')


def _json_error(ex: RecoveryError) -> JSONResponse:
    return JSONResponse({"error": ex.detail}, status_code=ex.status)


# ---------- forgot password ----------

@router.get("/reset", response_class=HTMLResponse)
def reset_page():
    body = f"""<section id="s-start"><h1>Reset your password</h1>
<p>Prove it's your account with the phone number or the email address verified on it.</p>
{_error_p()}
<form id="start-form">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" required>
<div class="choice"><label class="inline"><input type="radio" name="method" id="method-phone" value="phone" checked> Text my phone</label>
<label class="inline"><input type="radio" name="method" id="method-email" value="email"> Email me a link</label></div>
<div id="by-phone"><label for="phone">Phone number on the account</label>
<input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" placeholder="555 123 4567"></div>
<div id="by-email" hidden><label for="email">Verified email on the account</label>
<input id="email" name="email" type="email" autocomplete="email"></div>
<button type="submit">Continue</button>
</form>
<p class="small"><a href="/account/phone">Changed your phone number?</a></p></section>
{_proof_sections("/reset/prove")}"""
    return _page("Reset your password", body, {"start": "/reset/start", "landing": "/reset/email", "mode": "start"})


@router.post("/reset/start")
def reset_start(username: str = Form(""), method: str = Form("phone"), phone: str = Form(""), email: str = Form("")):
    try:
        return recovery.start(username, method, phone if method == "phone" else email, "reset", DB_PATH)
    except RecoveryError as ex:
        return _json_error(ex)


@router.get("/reset/email", response_class=HTMLResponse)
def reset_email_landing(f: str = ""):
    body = f'{_error_p()}<section id="s-wait"><h1>Signing you in…</h1></section>{_proof_sections("/reset/prove")}'
    return _page("Reset your password", body, {"mode": "landing", "flow": f})


def _password_step(code: str, error: str = "") -> HTMLResponse:
    body = f"""<h1>Choose a new password</h1>
{_error_p(error)}
<form method="post" action="/reset/complete">
<input type="hidden" name="f" value="{e(code)}">
<label for="password">New password (at least {recovery.MIN_PASSWORD} characters)</label>
<input id="password" name="password" type="password" autocomplete="new-password" minlength="{recovery.MIN_PASSWORD}" required>
<label for="password2">Type it again</label>
<input id="password2" name="password2" type="password" autocomplete="new-password" required>
<label for="recovery_code">Recovery code</label>
<input id="recovery_code" name="recovery_code" type="text" autocapitalize="characters" autocomplete="off"
 placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX">
<p class="warn">Your password also unlocks your wallets. With your recovery code they come back as they were.
Without it, your account comes back but your current wallets stay locked until you import a wallet backup.</p>
<label class="inline"><input type="checkbox" name="accept_locked" value="1"> I don't have my recovery code:
reset anyway</label>
<button type="submit">Set new password</button>
</form>"""
    return _page("Choose a new password", body)


@router.get("/reset/set", response_class=HTMLResponse)
def reset_set(f: str = ""):
    if not recovery.reset_ready(f, DB_PATH):
        return _expired("Reset your password", "This link has expired or was already used. Ask for a new one.",
                        "/reset")
    return _password_step(f)


@router.post("/reset/prove", response_class=HTMLResponse)
def reset_prove(f: str = Form(""), id_token: str = Form("")):
    try:
        recovery.prove(f, id_token, "reset", DB_PATH)
    except RecoveryError as ex:
        return _expired("Reset your password", ex.detail, "/reset")
    return _password_step(f)


@router.post("/reset/complete", response_class=HTMLResponse)
def reset_complete(request: Request, f: str = Form(""), password: str = Form(""), password2: str = Form(""),
                   recovery_code: str = Form(""), accept_locked: str = Form("")):
    if password != password2:
        return _password_step(f, "The two passwords don't match.")
    try:
        done = recovery.complete_reset(f, password, recovery_code, accept_locked == "1", DB_PATH)
    except RecoveryError as ex:
        if ex.status == 410:
            return _expired("Reset your password", ex.detail, "/reset")
        return _password_step(f, ex.detail)
    wallets = ("<p>Your wallets are unlocked with your new password, as before.</p>" if done["wallets"] == "kept" else
               "<p class=\"warn\">Your previous wallets are locked. Import your wallet backup in the app to "
               "unlock them; balances stay on the network meanwhile.</p>")
    body = f"""<h1>Password changed</h1>
<p>Account: <b>@{e(done['username'])}</b>. You've been signed out everywhere; log in with your new password.</p>
{wallets}
<h1>Your new recovery code</h1>
<p>Write it down and keep it somewhere safe. It's shown only once, and your old code no longer works.</p>
<p class="code">{e(done['recovery_code'])}</p>
{_back(request)}"""
    return _page("Password changed", body)


# ---------- changing the verified phone ----------

@router.get("/account/phone", response_class=HTMLResponse)
def phone_change_page():
    body = f"""<section id="s-start"><h1>Changed your phone number?</h1>
<p>Prove it's your account with the email address verified on it, then verify your new number.</p>
{_error_p()}
<form id="start-form"><input type="hidden" name="method" value="email">
<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" required>
<label for="email">Verified email on the account</label>
<input id="email" name="email" type="email" autocomplete="email" required>
<button type="submit">Email me a link</button></form></section>
{_proof_sections("/account/phone/prove")}"""
    return _page("Change your phone number", body, {"start": "/account/phone/start", "landing": "/account/phone/email",
                                                    "mode": "start"})


@router.post("/account/phone/start")
def phone_change_start(username: str = Form(""), email: str = Form("")):
    try:
        return recovery.start(username, "email", email, "phone", DB_PATH)
    except RecoveryError as ex:
        return _json_error(ex)


@router.get("/account/phone/email", response_class=HTMLResponse)
def phone_change_landing(f: str = ""):
    body = f'{_error_p()}<section id="s-wait"><h1>Signing you in…</h1></section>{_proof_sections("/account/phone/prove")}'
    return _page("Change your phone number", body, {"mode": "landing", "flow": f})


def _new_phone_step(code: str, error: str = "") -> HTMLResponse:
    body = f"""<section id="s-start"><h1>Your new number</h1>
<p>We'll text a code to the new number. It replaces the old one on your account.</p>
{_error_p(error)}
<form id="start-form"><label for="phone">New mobile number</label>
<input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel" required>
<button type="submit">Text me a code</button></form></section>
{_proof_sections("/account/phone/prove-new")}"""
    return _page("Your new number", body, {"start": "/account/phone/new", "mode": "start", "flow": code})


@router.post("/account/phone/prove", response_class=HTMLResponse)
def phone_change_prove(f: str = Form(""), id_token: str = Form("")):
    try:
        recovery.prove(f, id_token, "phone", DB_PATH)
    except RecoveryError as ex:
        return _expired("Change your phone number", ex.detail, "/account/phone")
    return _new_phone_step(f)


@router.post("/account/phone/new")
def phone_change_new(f: str = Form(""), phone: str = Form("")):
    try:
        return recovery.start_new_phone(f, phone, DB_PATH)
    except RecoveryError as ex:
        return _json_error(ex)


@router.post("/account/phone/prove-new", response_class=HTMLResponse)
def phone_change_prove_new(request: Request, f: str = Form(""), id_token: str = Form("")):
    try:
        username = recovery.prove_new_phone(f, id_token, DB_PATH)
    except RecoveryError as ex:
        if ex.status == 410:
            return _expired("Change your phone number", ex.detail, "/account/phone")
        return _new_phone_step(f, ex.detail)
    return _page("Phone number changed", f"""<h1>Phone number changed</h1>
<p>Account: <b>@{e(username)}</b>. Your new number is now the one on your account.</p>{_back(request)}""")


# ---------- verify an email (signed in) ----------

@router.post("/email/link")
def email_link(request: Request, caller: Caller = Depends(caller_from_form)):
    """A one-time link to verify an email address for the caller in a browser."""
    username = caller.require("post")
    return {"url": f"{_page_base(request)}/account/email?f={recovery.email_link(username, DB_PATH)}",
            "expires_in": int(recovery.FLOW_TTL.total_seconds())}


@router.get("/account/email", response_class=HTMLResponse)
def email_page(f: str = ""):
    username = recovery.flow_username(f, "email", DB_PATH)
    if not username:
        return _expired("Verify your email", "This link has expired. Open GFC and try again.", "/web")
    body = f"""<section id="s-start"><h1>Verify your email</h1>
<p>Account: <b>@{e(username)}</b>. A verified email lets you reset your password or change your phone
number if you lose access to it.</p>
{_error_p()}
<form id="start-form"><label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="email" required>
<button type="submit">Email me a link</button></form></section>
{_proof_sections("/account/email/prove")}"""
    return _page("Verify your email", body, {"start": "/account/email/start", "landing": "/account/email/done",
                                             "mode": "start", "flow": f})


@router.post("/account/email/start")
def email_start(f: str = Form(""), email: str = Form("")):
    try:
        return recovery.start_email(f, email, DB_PATH)
    except RecoveryError as ex:
        return _json_error(ex)


@router.get("/account/email/done", response_class=HTMLResponse)
def email_landing(f: str = ""):
    body = f'{_error_p()}<section id="s-wait"><h1>Signing you in…</h1></section>{_proof_sections("/account/email/prove")}'
    return _page("Verify your email", body, {"mode": "landing", "flow": f})


@router.post("/account/email/prove", response_class=HTMLResponse)
def email_prove(request: Request, f: str = Form(""), id_token: str = Form("")):
    try:
        done = recovery.prove_email(f, id_token, DB_PATH)
    except RecoveryError as ex:
        return _expired("Verify your email", ex.detail, "/web")
    return _page("Email verified", f"""<h1>Email verified</h1>
<p>Account: <b>@{e(done['username'])}</b>. <b>{e(done['email'])}</b> can now reset your password or change
your phone number.</p>{_back(request)}""")


# ---------- recovery code and status (signed in) ----------

@router.post("/account/recovery-code")
def recovery_code(password: str = Form(""), caller: Caller = Depends(caller_from_form)):
    """A new recovery code (the old one stops working). Needs the password again."""
    username = caller.require("post")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row[0]):
        return JSONResponse({"detail": "wrong password"}, status_code=401)
    data_key = keystore.unlock_user_keys(username, password)
    return {"recovery_code": keystore.new_recovery_code(username, data_key)}


@router.get("/account/security")
def security_status(caller: Caller = Depends(caller_from_query)):
    return recovery.status(caller.require("read"), DB_PATH)
