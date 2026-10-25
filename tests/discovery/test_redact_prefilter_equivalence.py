# Modified from Apache-2.0 licensed code; see THIRD_PARTY_NOTICES.txt.
"""Equivalence/fuzz check for the redact_text pre-filter (_could_be_secret).

The pre-filter is a conservative speed optimization: it may only skip values that
provably match no detect-secrets plugin. To prove it introduces NO false
negatives (a skipped secret = a leak), this runs redact_text over a large
adversarial corpus twice -- with the gate on, and with it forced off -- and
asserts byte-identical output.
"""

import random
import string

import pytest

import shepherd_scan._vendor.discovery.redact as redact_mod
from shepherd_scan._vendor.discovery.redact import redact_text

# Realistic known-format secrets the format detectors should catch regardless.
_KNOWN_FORMAT = [
    "AKIAIOSFODNN7EXAMPLE",  # AWS
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",  # GitHub PAT
    "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",  # Stripe
    "xoxb-123456789012-1234567890123-" + "abcdefghijklmnopqrstuvwx",  # Slack
    "glpat-" + "ABCDEF1234567890abcd",  # GitLab
]


def _rand_lower(rng, lo, hi):
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(lo, hi)))


def _rand_hexish(rng, lo, hi):
    return "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(lo, hi)))


def _rand_base64(rng, lo, hi):
    alphabet = string.ascii_letters + string.digits + "+/"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(lo, hi)))


def _rand_mixed(rng, lo, hi):
    alphabet = string.ascii_letters + string.digits + "-_.:/@"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(lo, hi)))


def _build_tokens(rng, n):
    tokens = []
    for _ in range(n):
        kind = rng.randint(0, 8)
        if kind == 0:  # short prose word (gate skips these)
            tokens.append(_rand_lower(rng, 1, 12))
        elif kind == 1:  # boundary-length pure-lowercase (21..25 around the cap of 22)
            tokens.append(_rand_lower(rng, 21, 25))
        elif kind == 2:  # long, high-distinct lowercase that CAN trip Base64 (>22 distinct)
            tokens.append("".join(rng.sample(string.ascii_lowercase, rng.randint(20, 26))))
        elif kind == 3:  # hex-ish (Hex detector territory)
            tokens.append(_rand_hexish(rng, 4, 40))
        elif kind == 4:  # base64-ish high entropy
            tokens.append(_rand_base64(rng, 8, 48))
        elif kind == 5:  # mixed punctuation/url-ish
            tokens.append(_rand_mixed(rng, 5, 40))
        elif kind == 6:  # known-format secret, sometimes wrapped in markup
            sec = rng.choice(_KNOWN_FORMAT)
            wrap = rng.randint(0, 3)
            tokens.append({0: sec, 1: f"`{sec}`", 2: f'"{sec}"', 3: f"url/{sec}?x=1"}[wrap])
        elif kind == 7:  # keyword-style assignment
            tokens.append(
                f"{rng.choice(['password', 'api_key', 'token'])}={_rand_base64(rng, 6, 30)}"
            )
        else:  # uppercase / digit noise
            tokens.append(
                "".join(
                    rng.choice(string.ascii_uppercase + string.digits)
                    for _ in range(rng.randint(1, 20))
                )
            )
    return tokens


@pytest.mark.parametrize("seed", [1, 7, 42, 20260618, 999999])
def test_prefilter_output_identical_to_unfiltered(seed, monkeypatch):
    rng = random.Random(seed)
    tokens = _build_tokens(rng, 4000)
    # Pack tokens into lines of random width so line/token structure varies.
    lines, i = [], 0
    while i < len(tokens):
        width = rng.randint(1, 12)
        lines.append(" ".join(tokens[i : i + width]))
        i += width
    text = "\n".join(lines)

    gated = redact_text(text)  # real _could_be_secret

    monkeypatch.setattr(redact_mod, "_could_be_secret", lambda value: True)  # disable gate
    ungated = redact_text(text)

    assert gated == ungated


def test_prefilter_skips_only_safe_tokens():
    """Spot-check the gate's contract on boundary cases."""
    # skipped (pure lowercase, <=22)
    cap = redact_mod._PROSE_MAX_LEN
    # skipped: pure ASCII-lowercase, length <= the cap
    assert redact_mod._could_be_secret("the") is False
    assert redact_mod._could_be_secret("a" * cap) is False
    # NOT skipped: one char over the cap, or any uppercase / digit / special / non-ascii
    assert redact_mod._could_be_secret("a" * (cap + 1)) is True
    assert redact_mod._could_be_secret("Configuration") is True
    assert redact_mod._could_be_secret("config1") is True
    assert redact_mod._could_be_secret("api_key") is True
    assert redact_mod._could_be_secret("café") is True
