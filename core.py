"""Step-Up policy: who is locked, who is unlocked, and for how long."""
import re
import threading
import time

from . import totp

LOCKOUT_SECONDS = 15 * 60
PENDING_SECONDS = 5 * 60
MAX_SESSIONS = 2000

DEFAULT_TOOLS = ["terminal", "execute_code"]
DEFAULT_PLATFORMS = ["telegram", "discord", "slack", "whatsapp", "signal",
                     "matrix", "mattermost", "sms", "email"]

_UNLOCK = re.compile(r"/?unlock\s+(\d{3})\s?(\d{3})", re.I)
_BARE = re.compile(r"(\d{3})\s?(\d{3})")
_LOCK = re.compile(r"/?lock", re.I)


def _field(obj, name):
    """Read a field from a dict-like or attribute-style object."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _ids(source, kwargs):
    """Every identifier that may equal the sender_id the agent turn reports."""
    found = []
    values = [_field(source, n) for n in ("user_id", "sender_id", "chat_id", "from_user_id", "author_id")]
    values.append(kwargs.get("sender_id"))
    for value in values:
        if value is not None and str(value) and str(value) not in found:
            found.append(str(value))
    return found


def _norm(value):
    return str(getattr(value, "value", value) or "").strip().lower()


class StepUp:
    def __init__(self, get_config, state, get_secret, clock=time.time):
        self._cfg = get_config
        self._state = state
        self._get_secret = get_secret
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions = {}

    # ---- settings -------------------------------------------------------
    def _list(self, key, default):
        value = self._cfg(key, default=default)
        if not isinstance(value, (list, tuple)):
            value = default
        return {_norm(v) for v in value}

    def _int(self, key, default):
        try:
            return max(1, int(self._cfg(key, default=default)))
        except (TypeError, ValueError):
            return default

    def _secret(self):
        try:
            return totp.normalize_secret(self._get_secret("STEPUP_TOTP_SECRET"))
        except Exception:
            return ""

    # ---- state ----------------------------------------------------------
    def _load(self):
        data = self._state.get("stepup", default={})
        if not isinstance(data, dict):
            data = {}
        for name in ("unlocks", "fails", "pending"):
            if not isinstance(data.get(name), dict):
                data[name] = {}
        if not isinstance(data.get("last_counter"), int):
            data["last_counter"] = -1
        return data

    def _save(self, data):
        now = self._clock()
        data["unlocks"] = {k: v for k, v in data["unlocks"].items() if v > now}
        data["pending"] = {k: v for k, v in data["pending"].items() if v > now}
        data["fails"] = {k: v for k, v in data["fails"].items()
                         if v.get("until", 0) > now or v.get("n", 0) > 0}
        self._state.set("stepup", data)

    # ---- hooks ----------------------------------------------------------
    def on_pre_llm_call(self, session_id="", platform="", **kwargs):
        """Remember which platform and sender each session belongs to."""
        platform = _norm(platform)
        sender = kwargs.get("sender_id")
        parent = kwargs.get("parent_session_id")
        with self._lock:
            if parent and parent in self._sessions and (not platform or sender is None):
                self._sessions[session_id] = self._sessions[parent]
            else:
                self._sessions[session_id] = (platform, "" if sender is None else str(sender))
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.pop(next(iter(self._sessions)))
        return None

    def on_pre_tool_call(self, tool_name="", args=None, task_id="", **kwargs):
        if _norm(tool_name) not in self._list("protected_tools", DEFAULT_TOOLS):
            return None
        with self._lock:
            ident = (self._sessions.get(kwargs.get("session_id") or "")
                     or self._sessions.get(task_id or ""))
        if not ident:
            return None  # local CLI/Desktop session, or one we never saw start
        platform, sender = ident
        if platform not in self._list("platforms", DEFAULT_PLATFORMS):
            return None
        if not self._secret():
            return {"action": "block", "message": (
                "Step-Up is enabled but STEPUP_TOTP_SECRET is not set, so protected "
                "tools are locked on messaging platforms. The owner must set the "
                "secret on the Hermes machine.")}
        key = "%s:%s" % (platform, sender)
        now = self._clock()
        with self._lock:
            data = self._load()
            if data["unlocks"].get(key, 0) > now:
                return None
            data["pending"][key] = now + PENDING_SECONDS
            self._save(data)
        return {"action": "block", "message": (
            "Step-Up lock: '%s' is locked in this chat. Tell the user to send the "
            "6-digit code from their authenticator app as a message here, then "
            "repeat the request. Do not try another tool to get around this."
            % tool_name)}

    def on_post_gateway_admission(self, session_key=None, platform=None,
                                  source=None, message_id=None, text=None, **kwargs):
        platform = _norm(platform or _field(source, "platform"))
        if platform not in self._list("platforms", DEFAULT_PLATFORMS):
            return None
        if not isinstance(text, str):
            return None
        body = text.strip()
        keys = ["%s:%s" % (platform, i) for i in _ids(source, kwargs)]
        if not keys:
            return None  # no sender identity: let the message through untouched
        now = self._clock()

        if _LOCK.fullmatch(body):
            with self._lock:
                data = self._load()
                for key in keys:
                    data["unlocks"].pop(key, None)
                self._save(data)
            return {"action": "handled", "reply": "🔒 Locked. Protected tools need a new code."}

        match = _UNLOCK.fullmatch(body)
        if not match:
            bare = _BARE.fullmatch(body)
            if not bare:
                return None
            with self._lock:
                pending = self._load()["pending"]
                waiting = any(pending.get(key, 0) > now for key in keys)
            if not waiting:
                return None  # an ordinary six-digit message, not for us
            match = bare
        code = match.group(1) + match.group(2)
        return {"action": "handled", "reply": self._attempt(keys, code, now)}

    # ---- unlock ---------------------------------------------------------
    def _attempt(self, keys, code, now):
        key = keys[0]
        secret = self._secret()
        if not secret:
            return "Step-Up has no secret configured on the Hermes machine."
        minutes = self._int("unlock_minutes", 10)
        limit = self._int("max_failures", 5)
        with self._lock:
            data = self._load()
            fail = data["fails"].get(key, {"n": 0, "until": 0})
            if fail.get("until", 0) > now:
                left = int((fail["until"] - now) // 60) + 1
                return "⛔ Too many wrong codes. Try again in %d min." % left
            try:
                counter = totp.verify(secret, code, now, data["last_counter"])
            except Exception:
                return "Step-Up secret is not valid Base32. Fix STEPUP_TOTP_SECRET."
            if counter is None:
                fail = {"n": fail.get("n", 0) + 1, "until": 0}
                if fail["n"] >= limit:
                    fail = {"n": 0, "until": now + LOCKOUT_SECONDS}
                    data["fails"][key] = fail
                    self._save(data)
                    return "⛔ Too many wrong codes. Locked out for 15 min."
                data["fails"][key] = fail
                self._save(data)
                return ("❌ Wrong or already-used code. %d attempt(s) left."
                        % (limit - fail["n"]))
            data["last_counter"] = counter
            for each in keys:
                data["unlocks"][each] = now + minutes * 60
                data["pending"].pop(each, None)
            data["fails"].pop(key, None)
            self._save(data)
        return ("🔓 Unlocked for %d min. Send your request again. "
                "Send 'lock' to lock early." % minutes)
