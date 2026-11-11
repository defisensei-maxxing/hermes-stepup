"""Step-Up: authenticator-app 2FA for Hermes Agent tool calls."""
from .core import StepUp


def _get_secret(name):
    from agent.secret_scope import get_secret
    return get_secret(name)


class _State:
    """Reach ctx.state only when a hook runs, never while registering."""

    def __init__(self, ctx):
        self._ctx = ctx

    def get(self, key, default=None):
        return self._ctx.state.get(key, default=default)

    def set(self, key, value):
        self._ctx.state.set(key, value)


def register(ctx):
    def get_config(key, default=None):
        return ctx.get_config(key, default=default)

    guard = StepUp(get_config, _State(ctx), _get_secret)
    ctx.register_hook("pre_llm_call", guard.on_pre_llm_call)
    ctx.register_hook("pre_tool_call", guard.on_pre_tool_call)
    ctx.register_hook("post_gateway_admission", guard.on_post_gateway_admission)
