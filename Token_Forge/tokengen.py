#!/usr/bin/env python3
"""edge-gateway internal sequence generator  (leaked from a core dump).

The gateway mints request-ids and the admin password-reset token from the
same sequence generator. `request_ids.log` holds consecutive ids (the
HIGH bits of successive states). `admin_reset.sealed` was sealed with the
NEXT state after the last logged id.
"""

A = 6364136223846793005
C = 1442695040888963407
MASK = (1 << 64) - 1
LOW_BITS = 32


def next_state(s: int) -> int:
    return (A * s + C) & MASK


def token(s: int) -> int:
    """Public id = top (64-LOW_BITS) bits of the state; low bits discarded."""
    return s >> LOW_BITS
