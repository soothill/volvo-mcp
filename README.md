# volvo-mcp

MCP server (streamable-http) for Volvo EVs (tested target: EX30 2024) using the
Volvo Cars connected-vehicle API.

Auth uses the **public PKCE client from the current Volvo Cars Android app**
(`mo2qy9h_10`, extracted from `se.volvo.vcc` 7.4/7.5 `AuthenticationConfig`).
The old shared client `h4Yf0b` (used by volvo2mqtt/evcc/Domoticz for years) was
revoked Volvo-wide on 2026-10-26 — see Dielee/volvo2mqtt#337. Volvo also refuses
`response_mode=pi.flow` for the new client, so login is the standard Keycloak
redirect flow (scriptable headless, or a browser).

## Tools
volvo_auth_status, volvo_auth_start, volvo_auth_finish, volvo_auth_otp (alias),
volvo_mail_probe, volvo_status, volvo_location, volvo_lock, volvo_unlock,
volvo_climate_start, volvo_climate_stop, volvo_charge_start, volvo_charge_stop,
volvo_statistics

## Config (env)
- VOLVO_VCC_API_KEY — free API key from https://developer.volvocars.com/account/
- VOLVO_CLIENT_ID — OAuth client (default `mo2qy9h_10`, the app's public client)
- VOLVO_REDIRECT_URI — must be registered for the client (default the app's
  `vca://www.volvocars.com/l/vca/oauth/callback`)
- VOLVO_CLIENT_SECRET — optional; only needed for a confidential client (the
  public PKCE flow sends no secret)
- VOLVO_USERNAME / VOLVO_PASSWORD — Volvo ID credentials; enable the **headless
  login** path (Keycloak form is scripted; only the OTP needs a source)
- VOLVO_OTP_IMAP_HOST — e.g. `imap.mail.me.com` (iCloud). Setting host + user +
  pass enables **automatic OTP retrieval**: after a headless login requests an
  OTP, the code is read from the newest matching Volvo email and the login
  completes unattended.
- VOLVO_OTP_IMAP_USER / VOLVO_OTP_IMAP_PASS — mailbox credentials (iCloud wants
  an app-specific password). Env vars or secret files `otp_imap_user` /
  `otp_imap_pass` under VOLVO_SECRET_DIR.
- VOLVO_OTP_IMAP_FOLDER (INBOX), VOLVO_OTP_SENDER (`volvocars.com`),
  VOLVO_OTP_KEYWORD (`code`), VOLVO_OTP_REGEX (`(?<!\d)(\d{6})(?!\d)`),
  VOLVO_OTP_WAIT_S (`90`) — tuning for the mail match.
- VOLVO_VIN — optional, else first vehicle on account
- VOLVO_UNIT — 1=km (default), 2/mi=miles
- VOLVO_TOKEN_PATH — writable path for OAuth tokens (default /data/volvo-token.json)
- MCP_HOST / MCP_PORT — default 0.0.0.0:8090, endpoint /mcp

## Login
**Headless (preferred, needs VOLVO_USERNAME/PASSWORD):** call `volvo_auth_start`.
- With VOLVO_OTP_IMAP_* configured it returns `{"result": "authenticated",
  "otp_source": "email"}` — fully unattended.
- Without, it returns `otp_required`; read the code from the Volvo email/app and
  call `volvo_auth_otp` with it.
- `volvo_mail_probe` verifies mailbox access (shows senders/subjects only,
  never codes) and is the tool to re-tune VOLVO_OTP_SENDER/KEYWORD/REGEX.

**Browser fallback:** `volvo_auth_start` → open `auth_url`, sign in, the browser
lands on a `vca://…?code=…` URL that fails to open (expected) → paste the FULL
address-bar URL into `volvo_auth_finish`.

The token is persisted and auto-refreshed thereafter. Note: developer-portal
clients die after ~7 days regardless of rotation (undocumented Volvo policy,
see evcc#22549); the app client has lasted months.
