"""Run each part of the scan on its own, so a part that fails or hangs costs only that part.

A part that raises, or that does not finish within its time limit, is replaced by an empty
result; the scan says so ("Not checked: ...") and goes on with the other parts, so the report
is written and the deep-check package is sent with whatever could be read. Ctrl-C still stops
the scan.
"""

import logging
import threading
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

# Generous limits: on a large computer the slowest part took well under a minute.
PART_SECONDS = 300.0
NOT_CHECKED = "Not checked:"

logger = logging.getLogger(__name__)


def attempt(
    part: str,
    run: Callable[[], T],
    default: T,
    failures: list[dict[str, str]] | None = None,
    *,
    seconds: float | None = None,
) -> T:
    """``run()``, or ``default`` when it raises or takes longer than ``seconds``.

    Args:
        part: What the part reads, in words the report can show ("saved sign-ins").
        run: The part.
        default: Its result when it fails, such as an empty list.
        failures: Where to record a failure as ``{"part", "reason"}``, if anywhere.
        seconds: A time limit; the part then runs on its own thread, which is left behind
            if it does not finish. None runs it here with no limit.

    Returns:
        The part's result, or ``default``.
    """
    if seconds is None:
        try:
            return run()
        except Exception as error:  # one part must not stop the scan
            return _failed(part, type(error).__name__, default, failures)
    outcome: list[T] = []
    errors: list[str] = []

    def target() -> None:
        try:
            outcome.append(run())
        except Exception as error:  # reported by the waiting thread
            errors.append(type(error).__name__)

    worker = threading.Thread(target=target, name=part, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        return _failed(part, f"did not finish within {seconds:.0f} seconds", default, failures)
    if errors or not outcome:
        return _failed(part, errors[0] if errors else "no result", default, failures)
    return outcome[0]


def _failed(part: str, reason: str, default: T, failures: list[dict[str, str]] | None) -> T:
    logger.warning("%s %s (%s)", NOT_CHECKED, part, reason)
    if failures is not None:
        failures.append({"part": part, "reason": reason})
    return default
