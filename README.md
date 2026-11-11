# Step-Up

Authenticator-app 2FA for your Hermes agent.

If Hermes is connected to Telegram, Discord or another messaging app, that chat
is a remote shell on your machine. Anyone holding your unlocked phone can use
it. Step-Up keeps the dangerous tools locked on messaging platforms until the
sender proves they are present with a one-time code from an authenticator app.

```
you:  run ls in my home folder
bot:  Terminal access is locked in this chat. Send the 6-digit code...
you:  000000
bot:  ❌ Wrong or already-used code. 4 attempt(s) left.
you:  492113
bot:  🔓 Unlocked for 10 min. Send your request again. Send 'lock' to lock early.
you:  run ls in my home folder
bot:  Applications  Desktop  Documents ...
```

## Why this is a plugin and not a prompt

A prompt can ask the model to check a code, and the model can be talked out of
it. Step-Up enforces the lock in code:

- `pre_tool_call` blocks the protected tool before it runs. If the hook errors
  or times out, Hermes fails closed.
- `post_gateway_admission` consumes the code message, so the code never reaches
  the model or the transcript sent to your provider.
- `pre_llm_call` only records which platform and sender a session belongs to.

## Install

1. Generate a secret (nothing is saved or sent):

   ```bash
   python3 tools/new_secret.py
   ```

2. Add it to an authenticator app (Google Authenticator, Authy, 1Password...)
   with "Enter a setup key", time-based.
3. Install the plugin and give Hermes the same secret when it asks for
   `STEPUP_TOTP_SECRET`:

   ```bash
   hermes plugins install stepup
   ```

4. Restart the gateway: `hermes gateway restart`.

## Using it

| You send | What happens |
|---|---|
| a request that needs a protected tool | blocked, the bot asks for a code |
| the 6-digit code | unlocks protected tools for you for 10 minutes |
| `unlock 123456` | same, works even when nothing is pending |
| `lock` | locks again immediately |

Each code works once. Five wrong codes lock that sender out for 15 minutes.
An unlock belongs to one sender on one platform; other people in a shared bot
stay locked.

## Settings

Under `plugins.entries.stepup.settings` in `config.yaml`:

| Key | Default | Meaning |
|---|---|---|
| `protected_tools` | `[terminal, execute_code]` | Tool names that need an unlock |
| `platforms` | telegram, discord, slack, whatsapp, signal, matrix, mattermost, sms, email | Where Step-Up enforces |
| `unlock_minutes` | `10` | Length of one unlock |
| `max_failures` | `5` | Wrong codes before the lockout |

Local CLI and Desktop sessions are never gated: if you are at the keyboard,
you are already present. Cron and other unattended runs are not gated either,
and nothing in Step-Up ever waits for input, so it cannot hang a run.

## What it does not do

- It does not replace Hermes approvals. It adds a gate in front of them and
  never approves anything on your behalf.
- It does not protect against someone with access to the machine itself.
- Tools outside `protected_tools` are not gated. Add the ones you care about.

## Disclosures

- Reads the text of incoming gateway messages to recognise a code, `unlock`
  and `lock`. Other messages pass through untouched.
- Holds one secret, `STEPUP_TOTP_SECRET`, read through Hermes's secret scope.
  It is never written to state or logs.
- Stores unlock expiry times, failure counts and the last used code counter in
  the plugin's own Hermes state.
- No network calls. No telemetry. No dependencies beyond the Python standard
  library.

## Tests

```bash
python3 tests/test_stepup.py
```

Covers RFC 6238 test vectors, replay, clock drift, lockout, expiry, per-sender
isolation and subagent inheritance.

## License

MIT
