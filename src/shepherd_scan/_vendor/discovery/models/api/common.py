# Modified from Apache-2.0 licensed code; see THIRD_PARTY_NOTICES.txt.
"""Wire models shared by supported analysis API versions."""

from pydantic import BaseModel


class ScanUserInfo(BaseModel):
    hostname: str | None = None
    username: list[str] | None = None
    identifier: str | None = None
    ip_address: str | None = None
    anonymous_identifier: str | None = None
