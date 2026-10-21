"""Volvo EX30 MCP server — wraps the Volvo Cars connected-vehicle API (volvo2mqtt-style privacy auth)."""
import base64
import json
import os
import time
from datetime import datetime, timedelta, timezone

import anyio
import requests
from mcp.server.mcpserver import MCPServer

OAUTH_TOKEN_URL = "https://volvoid.eu.volvocars.com/as/token.oauth2"
OAUTH_AUTH_URL = "https://volvoid.eu.volvocars.com/as/authorization.oauth2"
CLIENT_ID = "h4Yf0b"
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


def _env(name, default=None):
    return os.environ.get(name, default)

# Public app client secret embedded in Volvo's official mobile app (same value used by Dielee/volvo2mqtt)
CLIENT_SECRET = _env("VOLVO_CLIENT_SECRET", "U8YkSbVl6xwsg5YQqZfrgVmIaDphOsy1PCaUsicQto3TR5kwaJse4AZdgfIfcLyw")


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
        self._pending = None  # {"session":..., "data":...} during OTP login
        self._lock = __import__("threading").Lock()
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
            if not self.username:
                need.append("VOLVO_USERNAME")
            if not self.password:
                need.append("VOLVO_PASSWORD")
            if not self.vcc_key:
                need.append("VOLVO_VCC_API_KEY")
            return {"authenticated": False, "missing": need}
        return {"authenticated": True, "token_expires_at": self.expires_at.isoformat(),
                "vin": self.vin()}

    def login_start(self):
        if not self.username or not self.password:
            raise RuntimeError("VOLVO_USERNAME / VOLVO_PASSWORD not configured")
        s = requests.Session()
        s.headers.update({
            "authorization": "Basic " + base64.b64encode((CLIENT_ID + ":" + CLIENT_SECRET).encode()).decode(),
            "user-agent": UA,
            "Content-Type": "application/json; charset=utf-8",
        })
        params = ("?client_id=" + CLIENT_ID + "&response_type=code"
                  "&acr_values=urn:volvoid:aal:bronze:2sv&response_mode=pi.flow&scope=" + SCOPE)
        r = s.get(OAUTH_AUTH_URL + params, timeout=20)
        r.raise_for_status()
        data = r.json()
        status = data.get("status")
        if status == "COMPLETED":
            self._finish_login(s, data)
            return {"result": "authenticated"}
        if status == "USERNAME_PASSWORD_REQUIRED":
            s.headers.update({"x-xsrf-header": "PingFederate"})
            data = self._post_flow(s, data, "checkUsernamePassword",
                                   {"username": self.username, "password": self.password})
            status = data.get("status")
        if status in ("OTP_REQUIRED", "OTP_VERIFIED"):
            if status == "OTP_REQUIRED":
                self._pending = {"session": s, "data": data}
                return {"result": "otp_required",
                        "hint": "A one-time code was sent to your Volvo app/email. Call volvo_auth_otp with it."}
            data = self._post_flow(s, data, "continueAuthentication", {})
            status = data.get("status")
        if status == "COMPLETED":
            self._finish_login(s, data)
            return {"result": "authenticated"}
        raise RuntimeError("Unexpected auth state: %s" % status)

    def login_otp(self, code):
        if not self._pending:
            raise RuntimeError("No login in progress. Call volvo_auth_start first.")
        s, data = self._pending["session"], self._pending["data"]
        data = self._post_flow(s, data, "checkOtp", {"otp": code})
        data = self._post_flow(s, data, "continueAuthentication", {})
        self._pending = None
        self._finish_login(s, data)
        return {"result": "authenticated"}

    @staticmethod
    def _post_flow(s, data, action, body):
        href = data["_links"][action]["href"].replace("http://", "https://") + "?action=" + action
        r = s.post(href, data=json.dumps(body), timeout=20)
        if r.status_code != 200:
            try:
                msg = r.json()
            except ValueError:
                msg = r.text
            raise RuntimeError("%s failed: %s" % (action, msg))
        return r.json()

    def _finish_login(self, s, data):
        code = data["authorizeResponse"]["code"]
        s.headers.update({"content-type": "application/x-www-form-urlencoded"})
        r = s.post(OAUTH_TOKEN_URL, data={"code": code, "grant_type": "authorization_code"},
                   headers={"authorization": "Basic " + base64.b64encode((CLIENT_ID + ":" + CLIENT_SECRET).encode()).decode()},
                   timeout=20)
        if r.status_code != 200:
            raise RuntimeError("token exchange failed: %s" % r.text)
        self._save_token(r.json())

    def refresh(self):
        if not self.refresh_token:
            raise RuntimeError("Not authenticated. Use volvo_auth_start/volvo_auth_otp.")
        r = requests.post(OAUTH_TOKEN_URL,
                          data={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
                          headers={"authorization": "Basic " + base64.b64encode((CLIENT_ID + ":" + CLIENT_SECRET).encode()).decode(),
                                   "Content-Type": "application/x-www-form-urlencoded"},
                          timeout=20)
        if r.status_code != 200:
            raise RuntimeError("refresh failed: %s" % r.text)
        self._save_token(r.json())

    def ensure_auth(self):
        if not self.access_token:
            raise RuntimeError("Not authenticated. Use volvo_auth_start/volvo_auth_otp.")
        if datetime.now(timezone.utc) >= self.expires_at:
            self.refresh()

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
    """connected-vehicle v2 payloads: {"data":[{"group":..,"attributes":[{"id","value"}]}]}"""
    out = {}
    for grp in data.get("data", []):
        gname = grp.get("group") or grp.get("id") or ""
        for attr in grp.get("attributes", []):
            key = attr.get("id")
            if gname and gname != key:
                key = "%s.%s" % (gname, key)
            out[key] = attr.get("value")
    if "data" in out or not out:  # energy/state style: {"status": {...}}
        pass
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


@mcp.tool(description="Start Volvo ID login (username/password from env). Usually returns otp_required.")
async def volvo_auth_start():
    return _j(await anyio.to_thread.run_sync(client.login_start))


@mcp.tool(description="Submit the one-time code from the Volvo app/email to finish login.")
async def volvo_auth_otp(code: str):
    return _j(await anyio.to_thread.run_sync(lambda: client.login_otp(code)))


@mcp.tool(description="Full vehicle status: battery, range, charging, locks, windows, climate, odometer, tyres, location.")
async def volvo_status():
    def run():
        vin = client.vin()
        out = {"vin": vin}
        try:
            e = flatten(client.get(ENERGY.format(vin=vin)))
            soc = flat_get(e, "batteryChargeLevel", "battery_charge_level")
            rng = flat_get(e, "electricRange", "electric_range")
            out["battery_percent"] = soc
            v, u = _dist(rng)
            out["electric_range"] = {"value": v, "unit": u}
            out["charging_connection_status"] = flat_get(e, "chargingConnectionStatus", "charging_connection_status")
            out["charging_system_status"] = flat_get(e, "chargingSystemStatus", "charging_system_status")
            out["time_to_full_charge_min"] = flat_get(e, "timeToFullCharge", "estimated_charging_time", "time_to_full_charge")
        except Exception as ex:
            out["energy_error"] = str(ex)
        for name, url in (("doors", DOORS), ("windows", WINDOWS), ("tyres", TYRES)):
            try:
                out[name] = flatten(client.get(url.format(vin=vin)))
            except Exception as ex:
                out[name + "_error"] = str(ex)
        try:
            out["odometer"] = dict(zip(("value", "unit"), _dist(flat_get(flatten(client.get(ODOMETER.format(vin=vin))), "odometer", "value"))))
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
