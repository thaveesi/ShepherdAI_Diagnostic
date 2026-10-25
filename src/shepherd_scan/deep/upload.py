"""Pack the deep check's package and send it to Shepherd's drop box (Cloud Storage for Firebase).

The scanner signs in anonymously, so the person needs no account and the scanner carries no key:
the drop box's rules let an anonymous sign-in add one package to its own folder and nothing more.
"""

import io
import re
import secrets
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx

from shepherd_scan.deep.destination import FOLDER

SIGN_UP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
STORAGE_URL = "https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
ATTEMPTS = 3
TIMEOUT_SECONDS = 120
MAX_BYTES = 60 * 1024 * 1024
REFERENCE = re.compile(r"^\d{8}-[0-9a-f]{12}$")


class UploadError(Exception):
    """The upload could not be delivered."""


def pack(folder: Path) -> bytes:
    """The upload folder as one gzip-compressed tar archive, files in a fixed order."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path in sorted(folder.rglob("*")):
            try:
                if not path.is_file() or path.is_symlink():
                    continue
                data = path.read_bytes()
                info = tar.gettarinfo(path, arcname=path.relative_to(folder).as_posix())
            except OSError:  # a file that cannot be read is left out, not the package
                continue
            info.size = len(data)
            info.uname = info.gname = ""  # the Mac account name is not sent
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def new_reference() -> str:
    """A reference the person can quote: today's date and 12 random hexadecimal digits."""
    return f"{datetime.now(UTC):%Y%m%d}-{secrets.token_hex(6)}"


def send(
    archive: bytes, api_key: str, bucket: str, reference: str, client: httpx.Client | None = None
) -> str:
    """Upload the package to the drop box as ``uploads/<sign-in id>/<reference>.tar.gz``.

    Network problems and server errors are retried; a refusal is not.

    Returns:
        The reference.

    Raises:
        UploadError: If the package is too large, or the drop box refuses it or cannot be reached.
    """
    if len(archive) > MAX_BYTES:
        raise UploadError(f"the package is larger than {MAX_BYTES // (1024 * 1024)} MB")
    try:
        http = client or httpx.Client(timeout=TIMEOUT_SECONDS)
    except (ImportError, ValueError, OSError, httpx.InvalidURL) as error:
        raise UploadError(connection_problem(error)) from error
    try:
        sender, token = _sign_in(http, api_key)
        name = quote(f"{FOLDER}/{sender}/{reference}.tar.gz", safe="")
        url = f"{STORAGE_URL.format(bucket=bucket)}?uploadType=media&name={name}"
        headers = {"Authorization": f"Firebase {token}", "Content-Type": "application/gzip"}
        response = _call(http, http.build_request("POST", url, headers=headers, content=archive))
    finally:
        if client is None:
            http.close()
    if not response.is_success:
        raise UploadError(f"Shepherd refused the package ({response.status_code})")
    return reference


def connection_problem(error: Exception) -> str:
    """What stopped the connection from being set up, in words the person can act on."""
    if isinstance(error, ImportError):
        return (
            "this terminal is set to use a SOCKS proxy (all_proxy or https_proxy), which the "
            "deep check cannot use; run the scanner again in a terminal without that setting"
        )
    return (
        f"the connection could not be set up ({type(error).__name__}: {error}); check this "
        "terminal's proxy and certificate settings (all_proxy, https_proxy, no_proxy, "
        "SSL_CERT_FILE)"
    )


def _sign_in(http: httpx.Client, api_key: str) -> tuple[str, str]:
    """An anonymous sign-in: its id, which names the folder, and its token.

    Raises:
        UploadError: If the sign-in is refused or its answer cannot be read.
    """
    request = http.build_request(
        "POST", SIGN_UP_URL, params={"key": api_key}, json={"returnSecureToken": True}
    )
    response = _call(http, request)
    if not response.is_success:
        raise UploadError(f"the deep check could not sign in ({response.status_code})")
    try:
        data = response.json()
        return str(data["localId"]), str(data["idToken"])
    except (ValueError, KeyError, TypeError) as error:
        raise UploadError("the deep check could not read the sign-in answer") from error


def _call(http: httpx.Client, request: httpx.Request) -> httpx.Response:
    """Send one request, retried on network errors and server errors (5xx and 429).

    Raises:
        UploadError: If every attempt fails.
    """
    problem = ""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            response = http.send(request)
        except httpx.RequestError as error:
            problem = f"could not reach Shepherd ({type(error).__name__})"
        else:
            if response.status_code < 500 and response.status_code != 429:
                return response
            problem = f"Shepherd answered {response.status_code}"
        if attempt < ATTEMPTS:
            time.sleep(2**attempt)
    raise UploadError(problem)
