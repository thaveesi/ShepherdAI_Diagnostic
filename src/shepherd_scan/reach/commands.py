"""Decide whether a pre-approved command lets an agent run any program at all.

Agents let people pre-approve commands by prefix: approving ``git status`` approves only that,
but approving ``bash`` or ``npx`` with any arguments approves every program, because those
programs start whatever they are given. The lists below are fixed; nothing is run.
"""

import re
from pathlib import PurePath

SHELLS_AND_INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "pwsh", "powershell", "cmd",
    "node", "deno", "bun", "python", "python3", "ruby", "perl", "php", "lua", "osascript",
})  # fmt: skip
# Programs that run the command they are given.
WRAPPERS = frozenset({"env", "xargs", "exec", "eval", "sudo", "nohup", "timeout", "nice", "watch"})
# Programs that download and run a package named in their arguments.
PACKAGE_RUNNERS = frozenset({"npx", "bunx", "pnpx", "uvx", "pipx"})
# Package managers and container tools whose run and install commands execute any code.
PACKAGE_TOOLS = frozenset({"npm", "pnpm", "yarn", "pip", "pip3", "uv", "docker", "podman"})
RUN_VERBS = frozenset({"run", "exec", "dlx", "x", "install", "i", "add"})
# Interpreter options that take the program text itself.
CODE_OPTIONS = frozenset({"-c", "-e", "--eval", "-m", "-p", "--print", "-r"})

WILDCARD_SUFFIX = re.compile(r"(:\*|\s\*|\*)$")
# What may follow a literal command in an allow pattern for it to cover any arguments.
ANY_TAIL = re.compile(r"^(\\s\+?|\\s\*|\\b| )?(\.\*|\.\+)?\$?$")
MATCHES_ANYTHING = re.compile(r"^(\.\*|\.\+)?\$?$")
LITERAL_START = re.compile(r"[A-Za-z0-9_/~][A-Za-z0-9_./:@=-]*(?: [A-Za-z0-9_./:@=-]+)*")


def runs_any_program(prefix: str) -> bool:
    """Whether approving every command that starts with ``prefix`` approves any program.

    Args:
        prefix: The approved command prefix, such as ``uv run`` or ``npm run test``.

    Returns:
        True for an empty prefix, a shell or interpreter alone or followed only by a code
        option (``python3 -c``), a wrapper, a package runner alone, or a package tool alone or
        followed only by a run verb (``uv run``).
    """
    words = prefix.split()
    if not words:
        return True
    program = PurePath(words[0]).name.lower()
    rest = words[1:]
    if program in SHELLS_AND_INTERPRETERS or program in WRAPPERS:
        return not rest or (len(rest) == 1 and rest[0] in CODE_OPTIONS)
    if program in PACKAGE_RUNNERS:
        return not rest
    if program in PACKAGE_TOOLS:
        return not rest or (len(rest) == 1 and rest[0] in RUN_VERBS)
    return False


def command_prefix(spec: str) -> tuple[str, bool]:
    """Split an approval such as ``npm run:*`` into its prefix and whether more may follow."""
    text = spec.strip()
    if text in ("", "*", ":*"):
        return "", True
    stripped = WILDCARD_SUFFIX.sub("", text)
    return stripped.strip(), stripped != text


def regex_prefix(pattern: str) -> str | None:
    r"""The command prefix a regular-expression approval covers with any arguments, if any.

    ``^npm\s`` covers ``npm`` with anything after it, so it returns ``npm``; ``^git (status|diff)``
    restricts what follows, so it returns None. Patterns that match anything return ``""``.
    """
    body = pattern.strip()
    if len(body) >= 2 and body.startswith("/") and body.endswith("/"):
        body = body[1:-1]
    body = body.removeprefix("^")
    if MATCHES_ANYTHING.match(body):
        return ""
    match = LITERAL_START.match(body)
    literal = match.group(0) if match else ""
    return literal.strip() if ANY_TAIL.match(body[len(literal) :]) else None


def approval_runs_any_program(spec: str) -> bool:
    """Whether a prefix-style approval (``bash:*``, ``npx *``, ``*``) covers any program."""
    prefix, open_ended = command_prefix(spec)
    return open_ended and runs_any_program(prefix)


def describe(prefix: str) -> str:
    """How an approved prefix is shown in the report."""
    return prefix or "any command"
