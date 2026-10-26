"""Volvo EX30 MCP server — wraps the Volvo Cars connected-vehicle API (public PKCE OAuth, browser login)."""
import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import anyio
import requests
from mcp.server.mcpserver import MCPServer

OAUTH_TOKEN_URL = "https://volvoid.eu.volvocars.com/as/token.oauth2"
OAUTH_AUTH_URL = "https://volvoid.eu.volvocars.com/as/authorization.oauth2"
# h4Yf0b — the secret-bearing client extracted from the Volvo app and shared by
# volvo2mqtt / evcc / Domoticz for years — was revoked Volvo-wide on 2026-10-26
# (authorize answers "Unknown or invalid client_id" for everyone; Dielee/volvo2mqtt#337).
# mo2qy9h_10 is the client inside the current Volvo Cars Android app
# (se.volvo.vcc 7.4/7.5, AuthenticationConfig): a PUBLIC PKCE client with no
# secret, registered redirect below, and it accepts the conve:/energy: scopes.
# Volvo refuses response_mode=pi.flow for it, so login is a browser redirect.
CLIENT_ID = os.environ.get("VOLVO_CLIENT_ID", "mo2qy9h_10")
REDIRECT_URI = os.environ.get(
    "VOLVO_REDIRECT_URI", "vca://www.volvocars.com/l/vca/oauth/callback")
UA = "vca-android/3.12.0"
SCOPE = ("openid email profile care_by_volvo:financial_information:invoice:read "
         "care_by_volvo:financial_information:payment_method care_by_volvo:subscription:read "
         "customer:attributes customer:attributes:write order:attributes vehicle:attributes "
         "tsp_customer_api:all conve:brake_status conve:climatization_start_stop "
         "conve:command_accessibility conve:commands conve:diagnostics_engine_status "
         "conve:diagnostics_workshop conve:doors_status conve:engine_status conve:environment "
         "conve:fuel_status conve:honk_flash conve:lock conve:lock_status conve:navigation "
         "conve:odometer_status conve:trip_statistics conve:tyre_status conve:unlock "
         "conve:vehicle_relation conve:warnings conve:windows_status energy:battery_charge_level "
         "energy:charging_connection_status energy:charging_system_status energy:electric_range "
         "energy:estimated_charging_time energy:recharge_status vehicle:attributes")

BASE = "https://api.volvocars.com"
VEHICLES_URL = BASE + "/connected-vehicle/v2/vehicles"
DETAILS = VEHICLES_URL + "/{vin}"
DOORS = DETAILS + "/doors"
WINDOWS = DETAILS + "/windows"
ODOMETER = DETAILS + "/odometer"
TYRES = DETAILS + "/tyres"
ENGINE = DETAILS + "/engine-status"
STATISTICS = DETAILS + "/statistics"
WARNINGS = DETAILS + "/warnings"
LOC_URL = BASE + "/location/v1/vehicles/{vin}/location"
ENERGY = BASE + "/energy/v2/vehicles/{vin}/state"
CLIMATE_START = DETAILS + "/commands/climatization-start"
CLIMATE_STOP = DETAILS + "/commands/climatization-stop"
LOCK_CMD = DETAILS + "/commands/lock"
UNLOCK_CMD = DETAILS + "/commands/unlock"

KM_TO_MI = 0.621371

# A failed token refresh counts against Volvo's "too many failed logins" client
# lockout. volvo_status makes ~7 API calls per poll and each one used to attempt
# its own refresh, so one expired token turned into ~420 failed OAuth POSTs per
# hour at a 60s poll interval — which is what gets the client locked. Refreshes
# are now single-flight and back off exponentially after failing.
REFRESH_BACKOFF_BASE_S = 300
REFRESH_BACKOFF_MAX_S = 3600


def _env(name, default=None):
    return os.environ.get(name, default)

# The current app client is PUBLIC (PKCE): no secret is embedded or required.
# VOLVO_CLIENT_SECRET is still honoured if set (confidential-client compat),
# but the revoked h4Yf0b default is deliberately gone.
CLIENT_SECRET = _env("VOLVO_CLIENT_SECRET")
CLIENT_BASIC = (base64.b64encode((CLIENT_ID + ":" + CLIENT_SECRET).encode()).decode()
                if CLIENT_SECRET else None)


def _secret(name, filename):
    """Prefer env var; fall back to a secret file (first line, whitespace stripped)."""
    v = _env(name)
    if v:
        return v.strip()
    path = _env("VOLVO_SECRET_DIR", "/run/secrets/volvo") + "/" + filename
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _use_miles():
    return _env("VOLVO_UNIT", "1").strip().lower() in ("2", "mi", "miles", "usa")


def _dist(km):
    """Return (value, unit) converting km->mi when configured."""
    if km is None:
        return None, _unit()
    if _use_miles():
        return round(km * KM_TO_MI, 1), "mi"
    return km, "km"


def _unit():
    return "mi" if _use_miles() else "km"


class VolvoClient:
    def __init__(self):
        self.token_path = _env("VOLVO_TOKEN_PATH", "/data/volvo-token.json")
        self.username = _secret("VOLVO_USERNAME", "username")
        self.password = _secret("VOLVO_PASSWORD", "password")
        self.vcc_key = _secret("VOLVO_VCC_API_KEY", "vccapikey")
        self.vin_override = _env("VOLVO_VIN")
        self.access_token = None
        self.refresh_token = None
        self.expires_at = None
        self._vin = None
        self._pending = None  # {"verifier":..., "state":...} during browser login
        # A login interrupted by a container restart can be resumed if the
        # verifier survived on disk (the /data volume persists).
        try:
            with open(self.token_path + ".pending.json") as f:
                self._pending = json.load(f)
        except (OSError, ValueError):
            pass
        self._lock = __import__("threading").Lock()
        # Refresh failure state, so a broken token cannot turn into a login storm.
        self._refresh_failed_at = None
        self._refresh_attempts = 0
        self._refresh_error = None
        self.session = requests.Session()
        self._load_token()

    # ---------- token persistence ----------
    def _load_token(self):
        try:
            with open(self.token_path) as f:
                d = json.load(f)
            self.access_token = d["access_token"]
            self.refresh_token = d["refresh_token"]
            self.expires_at = datetime.fromisoformat(d["expires_at"])
            self._apply_auth()
        except (OSError, KeyError, ValueError):
            pass

    def _save_token(self, d):
        self.access_token = d["access_token"]
        self.refresh_token = d.get("refresh_token", self.refresh_token)
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(d["expires_in"]) - 30)
        self._apply_auth()
        tmp = self.token_path + ".tmp"
        os.makedirs(os.path.dirname(self.token_path) or ".", exist_ok=True)
        with open(tmp, "w") as f:
            json.dump({"access_token": self.access_token, "refresh_token": self.refresh_token,
                       "expires_at": self.expires_at.isoformat()}, f)
        os.replace(tmp, self.token_path)

    def _apply_auth(self):
        self.session.headers.update({"authorization": "Bearer " + self.access_token,
                                     "vcc-api-key": self.vcc_key or "",
                                     "user-agent": UA})

    # ---------- interactive login ----------
    def auth_status(self):
        if not self.access_token:
            need = []
            if not self.vcc_key:
                need.append("VOLVO_VCC_API_KEY")
            return {"authenticated": False, "missing": need}

        expired = datetime.now(timezone.utc) >= self.expires_at
        try:
            vin = self.vin()
        except Exception as exc:  # noqa: BLE001 - status must never itself raise
            vin = None
            out_vin_error = str(exc)[:200]
        else:
            out_vin_error = None
        out = {
            # "authenticated" used to mean "we have a token on file", which stayed
            # true for hours after it expired and misled callers into thinking
            # data was simply unavailable.
            "authenticated": not expired,
            "token_expires_at": self.expires_at.isoformat(),
            "token_expired": expired,
            "vin": vin,
        }
        if out_vin_error:
            out["vin_error"] = out_vin_error
        if self._refresh_attempts:
            out["refresh_attempts"] = self._refresh_attempts
            out["refresh_error"] = self._refresh_error
            out["refresh_retry_in_s"] = max(
                0, int(self._refresh_backoff_s()
                       - (datetime.now(timezone.utc) - self._refresh_failed_at).total_seconds()))
        if expired:
            out["action_required"] = (
                "token expired and refresh is not recovering it — run volvo_auth_start, "
                "open the returned auth_url in a browser, sign in with your Volvo ID, "
                "then call volvo_auth_finish with the final vca:// URL from the address bar")
        return out

    def login_start(self):
        """Begin a browser login and return the URL for the user to open.

        Volvo retired the scriptable pi.flow JSON endpoint for the current
        app client: mo2qy9h_10 answers "OAuth client is not allowed to
        initiate authentication API flow via the pi.flow response mode", so
        login is now the standard redirect flow. The user opens auth_url,
        signs in with their Volvo ID (the OTP step happens in the browser),
        and the browser finally lands on the app's custom-scheme redirect —
        which looks broken on a desktop because no app is registered for
        vca://. That is fine: the address-bar URL carries the authorisation
        code, and volvo_auth_finish exchanges it with the PKCE verifier held
        here. No username/password is stored or needed any more.
        """
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(16)
        url = (OAUTH_AUTH_URL
               + "?client_id=" + CLIENT_ID
               + "&response_type=code"
               + "&redirect_uri=" + urllib.parse.quote(REDIRECT_URI, safe="")
               + "&scope=" + urllib.parse.quote(SCOPE)
               + "&code_challenge=" + challenge
               + "&code_challenge_method=S256"
               + "&state=" + state)
        self._pending = {"verifier": verifier, "state": state}
        self._save_pending()
        return {
            "result": "browser_login_required",
            "auth_url": url,
            "instructions": (
                "Open auth_url in any browser and sign in with your Volvo ID "
                "(enter the OTP in the browser when asked). The browser ends "
                "on a vca:// URL that fails to open — expected. Copy the FULL "
                "final address-bar URL and call volvo_auth_finish with it."),
        }

    def login_finish(self, pasted):
        """Complete login with the redirect URL (or bare code) from the browser."""
        if not self._pending:
            raise RuntimeError("No login in progress. Call volvo_auth_start first.")
        pasted = pasted.strip()
        code, state = pasted, None
        if "code=" in pasted:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(pasted).query)
            code = (qs.get("code") or [None])[0]
            state = (qs.get("state") or [None])[0]
            if state and state != self._pending["state"]:
                raise RuntimeError("state mismatch — call volvo_auth_start again")
        if not code:
            raise RuntimeError("No authorisation code found. Paste the full redirected URL.")
        body = {"grant_type": "authorization_code", "code": code,
                "redirect_uri": REDIRECT_URI, "code_verifier": self._pending["verifier"]}
        headers = {"content-type": "application/x-www-form-urlencoded", "user-agent": UA}
        if CLIENT_BASIC:
            headers["authorization"] = "Basic " + CLIENT_BASIC
        else:
            body["client_id"] = CLIENT_ID
        r = requests.post(OAUTH_TOKEN_URL, data=body, headers=headers, timeout=20)
        if r.status_code != 200:
            raise RuntimeError("token exchange failed: HTTP %d %s" % (r.status_code, r.text[:300]))
        self._pending = None
        self._clear_pending()
        self._save_token(r.json())
        return {"result": "authenticated", "expires_at": self.expires_at.isoformat()}

    # Backwards-compatible alias: the OTP is now entered in the browser and the
    # thing that comes back is a redirect URL. Accept either so old muscle
    # memory (and the old tool name) keeps working.
    def login_otp(self, code):
        return self.login_finish(code)

    def _pending_path(self):
        return self.token_path + ".pending.json"

    def _save_pending(self):
        try:
            with open(self._pending_path(), "w") as f:
                json.dump(self._pending, f)
        except OSError:
            pass

    def _clear_pending(self):
        try:
            os.remove(self._pending_path())
        except OSError:
            pass

    def refresh(self):
        """Refresh the access token, single-flight and with exponential backoff.

        Callers used to each trigger their own refresh; with ~7 API calls per
        status poll that became a login storm against Volvo's OAuth endpoint and
        tripped the client lockout. Now only one thread refreshes, failures are
        remembered, and further attempts are suppressed until the backoff expires.
        """
        if not self.refresh_token:
            raise RuntimeError("Not authenticated. Use volvo_auth_start/volvo_auth_finish.")

        with self._lock:
            now = datetime.now(timezone.utc)
            # Another caller may have refreshed successfully while we queued here.
            if self.expires_at and now < self.expires_at:
                return
            if self._refresh_failed_at is not None:
                elapsed = (now - self._refresh_failed_at).total_seconds()
                if elapsed < self._refresh_backoff_s():
                    raise RuntimeError(
                        "token refresh suppressed for %ds after earlier failure (Volvo "
                        "rate/lockout protection): %s"
                        % (int(self._refresh_backoff_s() - elapsed), self._refresh_error)
                    )
            try:
                body = {"grant_type": "refresh_token",
                        "refresh_token": self.refresh_token}
                headers = {"Content-Type": "application/x-www-form-urlencoded",
                           "user-agent": UA}
                if CLIENT_BASIC:
                    headers["authorization"] = "Basic " + CLIENT_BASIC
                else:
                    # Public PKCE client: identifies itself in the body.
                    body["client_id"] = CLIENT_ID
                r = requests.post(OAUTH_TOKEN_URL, data=body, headers=headers, timeout=20)
                if r.status_code != 200:
                    raise RuntimeError("refresh failed: %s" % r.text[:300])
                self._save_token(r.json())
                # Success clears the failure state completely.
                self._refresh_failed_at = None
                self._refresh_attempts = 0
                self._refresh_error = None
            except Exception as exc:  # noqa: BLE001 - must record any failure
                self._refresh_failed_at = datetime.now(timezone.utc)
                self._refresh_attempts += 1
                self._refresh_error = str(exc)[:300]
                raise

    def _refresh_backoff_s(self):
        if not self._refresh_attempts:
            return 0
        return min(REFRESH_BACKOFF_BASE_S * (2 ** (self._refresh_attempts - 1)),
                   REFRESH_BACKOFF_MAX_S)

    def ensure_auth(self):
        if not self.access_token:
            raise RuntimeError("Not authenticated. Use volvo_auth_start/volvo_auth_finish.")
        if datetime.now(timezone.utc) >= self.expires_at:
            self.refresh()
            # A token that is still expired after a refresh attempt means the
            # refresh token is dead and only an interactive login will help.
            if datetime.now(timezone.utc) >= self.expires_at:
                raise RuntimeError(
                    "session expired and refresh did not recover it — run "
                    "volvo_auth_start + volvo_auth_finish to re-authenticate")

    # ---------- API ----------
    def vin(self):
        if self._vin:
            return self._vin
        if self.vin_override:
            self._vin = self.vin_override
            return self._vin
        self.ensure_auth()
        r = self.session.get(VEHICLES_URL, timeout=20)
        r.raise_for_status()
        vehicles = r.json()["data"]
        if not vehicles:
            raise RuntimeError("No vehicles on this Volvo account")
        self._vin = vehicles[0]["vin"]
        return self._vin

    def get(self, url):
        self.ensure_auth()
        r = self.session.get(url, timeout=20)
        if r.status_code != 200:
            raise RuntimeError("GET %s -> %s %s" % (url, r.status_code, r.text[:300]))
        return r.json()

    def post(self, url):
        self.ensure_auth()
        r = self.session.post(url, timeout=30)
        if r.status_code not in (200, 201, 204):
            raise RuntimeError("POST %s -> %s %s" % (url, r.status_code, r.text[:300]))
        try:
            return r.json()
        except ValueError:
            return {"ok": True}


def flatten(data):
    """Volvo API payloads:
    - {"data": {"name": {"value": v, "unit": u}, ...}}  (connected-vehicle v2)
    - {"name": {"value": v, ...}, ...}                   (energy v2 state)
    - {"data": [{"group": g, "attributes": [{"id","value"}]}]} (legacy)
    """
    out = {}
    payload = data.get("data", data) if isinstance(data, dict) else {}
    if isinstance(payload, dict):
        for key, val in payload.items():
            if isinstance(val, dict) and "value" in val:
                out[key] = val["value"]
            else:
                out[key] = val
    elif isinstance(payload, list):
        for grp in payload:
            gname = grp.get("group") or grp.get("id") or ""
            for attr in grp.get("attributes", []):
                k = attr.get("id")
                if gname and gname != k:
                    k = "%s.%s" % (gname, k)
                out[k] = attr.get("value")
    return out


def flat_get(data, *names):
    low = {k.lower(): v for k, v in data.items()}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    return None


client = VolvoClient()
mcp = MCPServer(name="volvo", instructions="Volvo EX30 status and control. Distances honour VOLVO_UNIT.")


def _j(obj):
    return json.dumps(obj, indent=1, default=str)


@mcp.tool(description="Auth state: whether the Volvo API token is present/valid and which secrets are missing.")
async def volvo_auth_status():
    return _j(client.auth_status())


@mcp.tool(description="Start Volvo ID login: returns auth_url to open in a browser (Volvo ID + OTP happen there).")
async def volvo_auth_start():
    try:
        return _j(await anyio.to_thread.run_sync(client.login_start))
    except Exception as exc:  # noqa: BLE001
        # The framework replaces exception text with a generic "Error executing
        # tool" for the MCP caller, so Volvo's actual explanation (lockout,
        # bad password, ...) never reached the operator. Return it in band.
        return _j({"result": "error", "error": str(exc)[:300]})


@mcp.tool(description="Finish login: paste the FULL final vca:// URL (or bare code) from the browser address bar.")
async def volvo_auth_finish(redirect_url: str):
    try:
        return _j(await anyio.to_thread.run_sync(lambda: client.login_finish(redirect_url)))
    except Exception as exc:  # noqa: BLE001
        return _j({"result": "error", "error": str(exc)[:300]})


@mcp.tool(description="Deprecated alias of volvo_auth_finish (the OTP is now entered in the browser).")
async def volvo_auth_otp(code: str):
    try:
        return _j(await anyio.to_thread.run_sync(lambda: client.login_otp(code)))
    except Exception as exc:  # noqa: BLE001
        return _j({"result": "error", "error": str(exc)[:300]})


@mcp.tool(description="Full vehicle status: battery, range, charging, locks, windows, climate, odometer, tyres, location.")
async def volvo_status():
    def run():
        # vin() calls ensure_auth(), so a dead token raises here before any
        # section is attempted. Letting that escape turns the whole tool into a
        # generic "Error executing tool volvo_status" and throws away the reason,
        # which is the one thing a wall display or health check needs.
        try:
            vin = client.vin()
        except Exception as ex:  # noqa: BLE001
            return {"vin": None, "vin_error": str(ex)[:300]}
        out = {"vin": vin}
        try:
            e = flatten(client.get(ENERGY.format(vin=vin)))
            soc = flat_get(e, "batteryChargeLevel", "battery_charge_level")
            rng = flat_get(e, "electricRange", "electric_range")
            out["battery_percent"] = soc
            v, u = _dist(rng)
            out["electric_range"] = {"value": v, "unit": u}
            out["charging_connection_status"] = flat_get(e, "chargerConnectionStatus", "chargingConnectionStatus")
            out["charging_system_status"] = flat_get(e, "chargingStatus", "chargingSystemStatus")
            out["charging_type"] = flat_get(e, "chargingType")
            out["time_to_full_charge_min"] = flat_get(e, "timeToFullCharge", "estimated_charging_time")
        except Exception as ex:
            out["energy_error"] = str(ex)
        for name, url in (("doors", DOORS), ("windows", WINDOWS), ("tyres", TYRES)):
            try:
                out[name] = flatten(client.get(url.format(vin=vin)))
            except Exception as ex:
                out[name + "_error"] = str(ex)
        try:
            od = flatten(client.get(ODOMETER.format(vin=vin)))
            v, u = _dist(od.get("odometer"))
            out["odometer"] = {"value": v, "unit": u}
        except Exception as ex:
            out["odometer_error"] = str(ex)
        try:
            out["engine_status"] = flatten(client.get(ENGINE.format(vin=vin)))
        except Exception:
            pass
        try:
            loc = client.get(LOC_URL.format(vin=vin))
            out["location"] = loc.get("data", loc)
        except Exception as ex:
            out["location_error"] = str(ex)
        return out
    return _j(await anyio.to_thread.run_sync(run))


@mcp.tool(description="Vehicle GPS location with accuracy.")
async def volvo_location():
    def run():
        vin = client.vin()
        d = client.get(LOC_URL.format(vin=vin))
        return d.get("data", d)
    return _j(await anyio.to_thread.run_sync(run))


@mcp.tool(description="Lock the vehicle.")
async def volvo_lock():
    return _j(await anyio.to_thread.run_sync(lambda: client.post(LOCK_CMD.format(vin=client.vin()))))


@mcp.tool(description="Unlock the vehicle.")
async def volvo_unlock():
    return _j(await anyio.to_thread.run_sync(lambda: client.post(UNLOCK_CMD.format(vin=client.vin()))))


@mcp.tool(description="Start remote climate/pre-conditioning.")
async def volvo_climate_start():
    return _j(await anyio.to_thread.run_sync(lambda: client.post(CLIMATE_START.format(vin=client.vin()))))


@mcp.tool(description="Stop remote climate/pre-conditioning.")
async def volvo_climate_stop():
    return _j(await anyio.to_thread.run_sync(lambda: client.post(CLIMATE_STOP.format(vin=client.vin()))))


def _charge_start():
    vin = client.vin()
    client.ensure_auth()
    r = client.session.post(BASE + "/energy/v2/vehicles/%s/state/charging" % vin,
                            json={"charging": "start"}, timeout=30)
    if r.status_code not in (200, 201, 204):
        raise RuntimeError("charge start -> %s %s" % (r.status_code, r.text[:300]))
    return {"result": "charging start requested"}


@mcp.tool(description="Start charging.")
async def volvo_charge_start():
    return _j(await anyio.to_thread.run_sync(_charge_start))


@mcp.tool(description="Stop charging.")
async def volvo_charge_stop():
    return _j(await anyio.to_thread.run_sync(_charge_stop))


def _charge_stop():
    vin = client.vin()
    client.ensure_auth()
    r = client.session.post(BASE + "/energy/v2/vehicles/%s/state/charging" % vin,
                            json={"charging": "stop"}, timeout=30)
    if r.status_code not in (200, 201, 204):
        raise RuntimeError("charge stop -> %s %s" % (r.status_code, r.text[:300]))
    return {"result": "charging stop requested"}


@mcp.tool(description="Trip statistics: averages, distance to empty, etc.")
async def volvo_statistics():
    def run():
        vin = client.vin()
        d = flatten(client.get(STATISTICS.format(vin=vin)))
        return d
    return _j(await anyio.to_thread.run_sync(run))


if __name__ == "__main__":
    host = _env("MCP_HOST", "0.0.0.0")
    port = int(_env("MCP_PORT", "8090"))
    mcp.run(transport="streamable-http", host=host, port=port)
