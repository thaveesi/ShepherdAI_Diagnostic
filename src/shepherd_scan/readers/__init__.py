"""Readers for agent apps beyond the built-in discovery list.

Importing this package adds each reader to the discovery registry, so a scan picks them up
alongside the built-in agents.
"""

from shepherd_scan._vendor.discovery.agents import DISCOVERERS
from shepherd_scan.readers.apps import READERS


def register_readers() -> None:
    """Add every reader to the discovery registry (idempotent)."""
    for reader in READERS:
        DISCOVERERS.setdefault(reader.name, reader)


register_readers()
