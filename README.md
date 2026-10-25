<p align="center"><img src="src/shepherd_scan/report/logo.png" alt="Shepherd" width="240"></p>

# Shepherd Scan

A free check of the AI agents on a Mac. It finds the AI apps and coding agents installed, the
servers and connectors they can use, the add-ons (skills and plugins) they load, keys left in
their settings, and the places where an agent can do more than you meant. It then writes a report
that opens in your browser.

The scan runs on your computer and sends nothing. At the end it offers an optional deep check;
nothing leaves your computer unless you say yes.

## Run it

You need macOS 13 (Ventura) or later, and an internet connection the first time: the scanner
downloads its own copy of uv and Python into its folder (about 200 MB). Nothing is installed
system-wide.

1. Download `shepherd-scan-<version>.zip` from the [latest release](https://github.com/thaveesi/ShepherdAI_Diagnostic/releases/latest).
2. Check the download against the checksum published with the release:

   ```bash
   shasum -a 256 shepherd-scan-<version>.zip
   ```

3. Unzip it, open Terminal in the unzipped folder and run:

   ```bash
   ./shepherd-scan
   ```

The report is saved in that folder and opens in your browser.

Options: `--no-open` (do not open the browser), `-o PATH` (where to save the report),
`--json PATH` (also save the findings as JSON), `--no-deep` (do not offer the deep check),
`--start-local-servers` (start local MCP servers to list their tools; it asks first),
`--verbose`.

## What it looks at

It reads the settings of AI agents and apps in your home folder (for example `~/.claude`,
`~/.cursor`, `~/.codex` and app folders under `~/Library/Application Support`), the skills and
plugins they load, and the list of installed applications. It reads settings; it never changes
them.

## The optional deep check

After the report is written, the scanner explains the deep check and asks before anything is
sent. If you say yes:

- We’ll receive a copy of your agent settings, add-on files, connector tool lists, session
  settings, AI app list and usage totals for review. Conversations are excluded.
- Detected passwords and API keys are redacted, along with usernames in file paths and email
  addresses in settings. Credential findings include only type and location.
- Access is limited to us. We delete our copies of submitted information after your report and
  any requested corrections are complete.

A copy of exactly what is sent is kept in a folder next to your report. The scanner shows a
reference at the end; quote it when you contact us.

## Remove it

Delete the folder you unzipped. If you ran the deep check, also delete `~/.cache/codeburn`, a
small cache left by the usage meter.

## Build from source

```bash
uv build
mkdir -p dist/shepherd-scan-<version>
cp packaging/shepherd-scan dist/shepherd_scan-<version>-py3-none-any.whl dist/shepherd-scan-<version>/
```

Run the tests with `uv sync` and then `uv run pytest`. On macOS, run the source tree with
`PYTHONPATH=src uv run python -m shepherd_scan`.

## Security, privacy and licence

- The licence lets you read the code and run it, but not copy or reuse it: [LICENSE](LICENSE).
- What the scanner does on your computer: [SECURITY.md](SECURITY.md).
- How the deep check handles your information: [PRIVACY.md](PRIVACY.md).
- Third-party components and their licences: [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
