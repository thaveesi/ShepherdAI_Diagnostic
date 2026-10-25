import pytest

from shepherd_scan.reach.commands import (
    approval_runs_any_program,
    command_prefix,
    regex_prefix,
    runs_any_program,
)


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "bash",
        "python3",
        "python3 -c",
        "node -e",
        "/usr/bin/env",
        "xargs",
        "sudo",
        "npx",
        "uvx",
        "npm",
        "npm run",
        "npm install",
        "uv run",
        "pip install",
        "venv/bin/pip install",
        "docker",
        "docker run",
    ],
)
def test_prefixes_that_start_any_program(prefix):
    assert runs_any_program(prefix)


@pytest.mark.parametrize(
    "prefix",
    [
        "git status",
        "ls -la",
        "python3 script.py",
        "python3 -m pytest",
        "npx prettier",
        "npm run test",
        "uv run pytest",
        "docker ps",
        "find",
        "make",
    ],
)
def test_specific_commands_do_not(prefix):
    assert not runs_any_program(prefix)


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("npm run:*", ("npm run", True)),
        ("npm run test *", ("npm run test", True)),
        ("*", ("", True)),
        ("", ("", True)),
        ("git status", ("git status", False)),
    ],
)
def test_command_prefix(spec, expected):
    assert command_prefix(spec) == expected


def test_approvals_need_open_arguments_to_cover_any_program():
    assert approval_runs_any_program("bash:*")
    assert approval_runs_any_program("*")
    assert not approval_runs_any_program("bash")
    assert not approval_runs_any_program("npm run test:*")


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"^npm\s", "npm"),
        (r"^npx\s+.*", "npx"),
        (r"/^bash\b/", "bash"),
        (".*", ""),
        (r"^git (status|diff)", None),
        (r"^cargo\s+test\s+--release", None),
    ],
)
def test_regex_prefix(pattern, expected):
    assert regex_prefix(pattern) == expected
