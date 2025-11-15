# beta_access.py
"""
Simple Early Access beta gate for Curator Finder.

Environment variables:

  CF_BETA_CODE        - The required beta code (what you ship to testers)
  CF_BETA_CODE_USER   - The code the user has entered (from their .env)
  CF_BETA_EXPIRY      - Expiry date for this beta build

Expiry formats supported:
  - "YYYY-MM-DD"              (interpreted as that date at 23:59:59 UTC)
  - Full ISO-8601-ish, e.g. "2025-12-31T23:59:59Z" or "2025-12-31 23:59"

If *none* of CF_BETA_CODE / CF_BETA_EXPIRY are set, the gate is treated as
"disabled" (useful for local dev). When you ship a beta, set all three.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any


@dataclass
class BetaStatus:
    ok: bool
    mode: str          # "disabled" | "enabled"
    reason: str        # machine-readable reason (e.g. "ok", "bad-code", ...)
    message: str       # human-readable message
    expires_at: Optional[datetime] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "mode": self.mode,
            "reason": self.reason,
            "message": self.message,
            "expires_at": int(self.expires_at.timestamp()) if self.expires_at else None,
            "expires_at_iso": self.expires_at.isoformat() if self.expires_at else None,
        }


def _get_env(name: str) -> str:
    return (os.getenv(name) or "").strip()


def _parse_expiry(raw: str) -> Optional[datetime]:
    """
    Parse CF_BETA_EXPIRY into an aware UTC datetime.
    Accepts:
      - YYYY-MM-DD
      - Any datetime string that datetime.fromisoformat can handle.
    """
    raw = (raw or "").strip()
    if not raw:
        return None

    # Date-only (YYYY-MM-DD)
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        # End of the day in UTC
        dt = datetime.strptime(raw, "%Y-%m-%d")
        return dt.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)

    # Try ISO-like formats
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def check_beta_access(now: Optional[datetime] = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Core check used by both server and desktop launcher.

    Returns (ok, info_dict) where info_dict has:
      { ok, mode, reason, message, expires_at, expires_at_iso }
    """
    now = now or datetime.now(timezone.utc)

    required = _get_env("CF_BETA_CODE")
    user     = _get_env("CF_BETA_CODE_USER")
    exp_raw  = _get_env("CF_BETA_EXPIRY")

    # If nothing is configured, treat as gate disabled (dev mode)
    if not required and not exp_raw:
        status = BetaStatus(
            ok=True,
            mode="disabled",
            reason="beta-disabled",
            message="Beta gate disabled (no CF_BETA_* env set).",
            expires_at=None,
        )
        return True, status.as_dict()

    # Gate is enabled once either code or expiry is set
    exp_dt = _parse_expiry(exp_raw)
    if not required:
        status = BetaStatus(
            ok=False,
            mode="enabled",
            reason="missing-required-code",
            message="CF_BETA_CODE is not set on this build.",
            expires_at=exp_dt,
        )
        return False, status.as_dict()

    if not user:
        status = BetaStatus(
            ok=False,
            mode="enabled",
            reason="missing-user-code",
            message="Beta code is required. Set CF_BETA_CODE_USER in your .env.",
            expires_at=exp_dt,
        )
        return False, status.as_dict()

    if user != required:
        status = BetaStatus(
            ok=False,
            mode="enabled",
            reason="bad-code",
            message="Invalid beta code. Check the code you were given.",
            expires_at=exp_dt,
        )
        return False, status.as_dict()

    if not exp_dt:
        status = BetaStatus(
            ok=False,
            mode="enabled",
            reason="missing-expiry",
            message="CF_BETA_EXPIRY is not set or has a bad format.",
            expires_at=None,
        )
        return False, status.as_dict()

    if now > exp_dt:
        status = BetaStatus(
            ok=False,
            mode="enabled",
            reason="expired",
            message=f"This Early Access build expired on {exp_dt.date().isoformat()}.",
            expires_at=exp_dt,
        )
        return False, status.as_dict()

    # All checks passed
    status = BetaStatus(
        ok=True,
        mode="enabled",
        reason="ok",
        message="Beta access granted.",
        expires_at=exp_dt,
    )
    return True, status.as_dict()


def assert_beta_or_exit() -> None:
    """
    Helper for CLI / desktop entrypoints.

    Prints a brief Early Access splash, then exits if beta access is not OK.
    """
    ok, info = check_beta_access()
    print("==========================================")
    print("  Curator Finder – Early Access Preview")
    print("==========================================")
    msg = info.get("message") or ""
    mode = info.get("mode") or "enabled"
    exp_iso = info.get("expires_at_iso")

    if exp_iso:
        print(f"  Beta expiry: {exp_iso}")
    print(f"  Beta mode: {mode}")
    print(f"  Status: {msg}")
    print("")

    if not ok:
        print("  This build is locked by the beta gate.")
        print("  Please check your .env settings (CF_BETA_CODE, CF_BETA_CODE_USER, CF_BETA_EXPIRY).")
        print("")
        sys.exit(1)

