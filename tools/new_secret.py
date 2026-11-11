#!/usr/bin/env python3
"""Print a fresh TOTP secret for Step-Up. Run locally; nothing is saved or sent."""
import base64
import secrets

secret = base64.b32encode(secrets.token_bytes(20)).decode()
print("Secret (enter this in your authenticator app as a setup key, time-based):")
print("  " + secret)
print()
print("Or as a URI:")
print("  otpauth://totp/Hermes:Step-Up?secret=%s&issuer=Hermes" % secret)
print()
print("Give the same secret to Hermes when it asks for STEPUP_TOTP_SECRET.")
