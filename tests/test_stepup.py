import base64, sys, types
import os, importlib.util
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("stepup", os.path.join(ROOT, "__init__.py"), submodule_search_locations=[ROOT])
sys.modules["stepup"] = importlib.util.module_from_spec(spec); spec.loader.exec_module(sys.modules["stepup"])
import stepup
from stepup.core import StepUp
from stepup import totp

SECRET = base64.b32encode(b"12345678901234567890").decode()
class State:
    def __init__(s): s.d = {}
    def get(s, k, default=None): return s.d.get(k, default)
    def set(s, k, v): s.d[k] = v
class Clock:
    t = 1_800_000_000.0
    def __call__(s): return s.t
def cfg(key, default=None): return default
def mk(secret=SECRET):
    c = Clock(); return StepUp(cfg, State(), lambda n: secret, clock=c), c
src = types.SimpleNamespace(user_id=4242, platform="telegram", chat_id=4242)
def code(c, off=0): return totp.code_at(SECRET, int(c.t)//30 + off)
def msg(g, text): return g.on_post_gateway_admission(session_key="k", platform="telegram", source=src, message_id="1", text=text)
n = 0
def ok(cond, name):
    global n; assert cond, name; n += 1

# RFC vectors (8-digit expected values truncated to 6)
for t, exp in [(59,"287082"),(1111111109,"081804"),(1234567890,"005924"),(2000000000,"279037")]:
    ok(totp.code_at(SECRET, t//30) == exp, "rfc %s" % t)

g, c = mk()
g.on_pre_llm_call(session_id="s1", platform="telegram", sender_id="4242", user_message="hi")
g.on_pre_llm_call(session_id="cli", platform="cli", user_message="hi")
ok(g.on_pre_tool_call("read_file", {}, "", session_id="s1") is None, "unprotected tool passes")
ok(g.on_pre_tool_call("terminal", {}, "", session_id="cli") is None, "cli never gated")
ok(g.on_pre_tool_call("terminal", {}, "", session_id="unknown") is None, "unknown session passes")
r = g.on_pre_tool_call("terminal", {"command": "rm -rf logs"}, "", session_id="s1")
ok(r["action"] == "block" and r["message"], "telegram terminal blocked")
ok(msg(g, "what is 123456 plus 1") is None, "normal text ignored")
r = msg(g, "000000"); ok(r["action"] == "handled" and "Wrong" in r["reply"] and "4 attempt" in r["reply"], "wrong code")
ok(g.on_pre_tool_call("terminal", {}, "", session_id="s1")["action"] == "block", "still blocked")
good = code(c)
r = msg(g, good); ok("Unlocked" in r["reply"], "bare code unlocks when pending")
ok(g.on_pre_tool_call("terminal", {}, "", session_id="s1") is None, "terminal passes after unlock")
ok(g.on_pre_tool_call("execute_code", {}, "", session_id="s1") is None, "execute_code passes too")
r = msg(g, "unlock " + good); ok("Wrong or already-used" in r["reply"], "replay refused")
ok(msg(g, "lock")["reply"].startswith("🔒"), "lock command")
ok(g.on_pre_tool_call("terminal", {}, "", session_id="s1")["action"] == "block", "blocked after lock")
c.t += 601 + 30
g2, c2 = mk()
ok(msg(g2, code(c2)) is None, "bare six digits ignored with nothing pending")
r = msg(g2, "/unlock " + code(c2)[:3] + " " + code(c2)[3:]); ok("Unlocked" in r["reply"], "/unlock with spaced code")
g2.on_pre_llm_call(session_id="s2", platform="telegram", sender_id=4242)
ok(g2.on_pre_tool_call("terminal", {}, "", session_id="s2") is None, "int sender id matches")
c2.t += 10*60 + 1
ok(g2.on_pre_tool_call("terminal", {}, "", session_id="s2")["action"] == "block", "expires after 10 min")
# other sender stays locked
g2.on_pre_llm_call(session_id="s3", platform="telegram", sender_id="999")
msg(g2, "unlock " + code(c2))
ok(g2.on_pre_tool_call("terminal", {}, "", session_id="s3")["action"] == "block", "unlock is per sender")
# subagent inherits parent
g2.on_pre_llm_call(session_id="child", platform="", parent_session_id="s3")
ok(g2.on_pre_tool_call("terminal", {}, "", session_id="child")["action"] == "block", "subagent inherits lock")
# lockout
g3, c3 = mk()
for i in range(4): msg(g3, "unlock 000000")
r = msg(g3, "unlock 000000"); ok("Locked out" in r["reply"], "lockout on 5th")
r = msg(g3, "unlock " + code(c3)); ok("Too many" in r["reply"], "good code refused during lockout")
c3.t += 15*60 + 1
ok("Unlocked" in msg(g3, "unlock " + code(c3))["reply"], "works after lockout")
# drift
g4, c4 = mk(); ok("Unlocked" in msg(g4, "unlock " + code(c4, -1))["reply"], "previous step accepted")
g5, c5 = mk(); ok("Wrong" in msg(g5, "unlock " + code(c5, -2))["reply"], "two steps old refused")
# missing / bad secret
g6, c6 = mk(secret="")
g6.on_pre_llm_call(session_id="s", platform="telegram", sender_id="1")
ok("STEPUP_TOTP_SECRET" in g6.on_pre_tool_call("terminal", {}, "", session_id="s")["message"], "missing secret blocks with hint")
g7, c7 = mk(secret="not base32 !!")
ok("Base32" in msg(g7, "unlock 123456")["reply"], "bad secret reported")
# register wiring
hooks = {}
ctx = types.SimpleNamespace(get_config=cfg, state=State(), register_hook=lambda n, f: hooks.__setitem__(n, f))
stepup.register(ctx)
ok(sorted(hooks) == ["post_gateway_admission", "pre_llm_call", "pre_tool_call"], "register wires 3 hooks")
# Hermes 0.23.1 passes source as a dict
gd, cd_ = mk()
dsrc = {"platform": "telegram", "user_id": "5550001176", "chat_id": "5550001176", "chat_type": "dm"}
def dmsg(g, text): return g.on_post_gateway_admission(session_key="k", platform="telegram", source=dsrc, message_id="1", text=text, telemetry_schema_version=1)
gd.on_pre_llm_call(session_id="sd", platform="telegram", sender_id="5550001176")
ok(gd.on_pre_tool_call("terminal", {}, "sd", session_id="sd")["action"] == "block", "dict: blocked")
ok("Wrong" in dmsg(gd, "000000")["reply"], "dict: wrong code handled")
ok("Unlocked" in dmsg(gd, code(cd_))["reply"], "dict: bare code unlocks")
ok(gd.on_pre_tool_call("terminal", {}, "sd", session_id="sd") is None, "dict: passes after unlock")
ok(dmsg(gd, "lock")["action"] == "handled" and gd.on_pre_tool_call("terminal", {}, "sd", session_id="sd")["action"] == "block", "dict: lock relocks")
# only chat_id matches the sender
ge, ce = mk()
ge.on_pre_llm_call(session_id="se", platform="telegram", sender_id="777")
ge.on_pre_tool_call("terminal", {}, "se", session_id="se")
r = ge.on_post_gateway_admission(platform="telegram", source={"user_id": None, "chat_id": 777}, text=code(ce))
ok(r and "Unlocked" in r["reply"] and ge.on_pre_tool_call("terminal", {}, "se", session_id="se") is None, "chat_id fallback")
# no identity at all: untouched
ok(mk()[0].on_post_gateway_admission(platform="telegram", source={}, text="unlock 123456") is None, "no identity passes through")
# a bare probe context (as the catalog validator uses) must still register
probe_hooks = {}
stepup.register(types.SimpleNamespace(register_hook=lambda n, f: probe_hooks.__setitem__(n, f)))
ok(len(probe_hooks) == 3, "registers on a context with no state or config")
# and the wired hooks work end to end through a real-shaped ctx
st = State(); wired = {}
stepup.register(types.SimpleNamespace(get_config=cfg, state=st, register_hook=lambda n, f: wired.__setitem__(n, f)))
wired["pre_llm_call"](session_id="w", platform="telegram", sender_id="9")
ok(wired["pre_tool_call"]("terminal", {}, "w", session_id="w")["action"] == "block", "wired hooks block")
lazy = stepup._State(types.SimpleNamespace(state=st))
lazy.set("k", 5)
ok(lazy.get("k", default=0) == 5 and st.d["k"] == 5, "state is reached lazily through ctx")
print("passed", n, "checks")
