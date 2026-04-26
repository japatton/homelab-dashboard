"""Path-injection guard for claude_runner.apply_change.

CodeQL's py/path-injection alert flags the shutil.copy2 source path as
user-influenced (it traces from the /api/claude/approve URL param all
the way to the DB → generated_files → src). Today the only writer of
that DB column is server-internal, so the values are trusted. The
guard added in apply_change is defense-in-depth: it requires every
src to live under sandbox_dir; anything outside is skipped with a
log line.

We cover:
  - happy path (file inside sandbox is copied)
  - escape attempt (absolute path outside sandbox is refused)
  - traversal attempt (symlink + ../ that resolves outside is refused)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from services.claude_runner import apply_change


pytestmark = pytest.mark.asyncio


async def test_apply_change_copies_file_inside_sandbox(tmp_path, monkeypatch):
    sandbox = tmp_path / "homelab-claude-abc123"
    sandbox.mkdir()
    (sandbox / "integration.py").write_text("DEVICE_TYPE = 'test'\n")

    integrations_dir = tmp_path / "active"
    monkeypatch.setattr("services.claude_runner.INTEGRATIONS_DIR", integrations_dir)

    copied = await apply_change(
        change_id="ch-fk-test-12345",
        sandbox_dir=str(sandbox),
        generated_files=[str(sandbox / "integration.py")],
    )

    assert len(copied) == 1
    dest = Path(copied[0])
    assert dest.parent == integrations_dir
    assert dest.name == "ch-fk-te_integration.py"
    assert dest.read_text() == "DEVICE_TYPE = 'test'\n"


async def test_apply_change_refuses_path_outside_sandbox(tmp_path, monkeypatch):
    sandbox = tmp_path / "homelab-claude-abc123"
    sandbox.mkdir()
    # Pretend the DB row points at /etc/passwd. Without the sandbox-
    # root check this would copy /etc/passwd into INTEGRATIONS_DIR.
    outside = tmp_path / "outside.py"
    outside.write_text("# host file\n")

    integrations_dir = tmp_path / "active"
    monkeypatch.setattr("services.claude_runner.INTEGRATIONS_DIR", integrations_dir)

    copied = await apply_change(
        change_id="ch-escape-test",
        sandbox_dir=str(sandbox),
        generated_files=[str(outside)],
    )

    assert copied == [], "outside-of-sandbox path should be refused"
    # And nothing should have landed in INTEGRATIONS_DIR
    assert not integrations_dir.exists() or not list(integrations_dir.iterdir())


async def test_apply_change_refuses_traversal_via_dotdot(tmp_path, monkeypatch):
    """A literal ../etc/passwd-shaped path: Path.resolve() collapses
    the ../, so the relative_to(sandbox_root) check trips correctly."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    target = tmp_path / "secret.py"
    target.write_text("# secret\n")

    integrations_dir = tmp_path / "active"
    monkeypatch.setattr("services.claude_runner.INTEGRATIONS_DIR", integrations_dir)

    # Construct a path that LOOKS like it's in sandbox but resolves out:
    # sandbox/../secret.py → tmp_path/secret.py, which is NOT under sandbox.
    traversal = sandbox / ".." / "secret.py"

    copied = await apply_change(
        change_id="ch-trav-test",
        sandbox_dir=str(sandbox),
        generated_files=[str(traversal)],
    )

    assert copied == []


async def test_apply_change_skips_missing_file_quietly(tmp_path, monkeypatch):
    """Sandbox-root check passes but the file doesn't exist — the
    pre-existing 'Generated file missing' branch should fire."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    integrations_dir = tmp_path / "active"
    monkeypatch.setattr("services.claude_runner.INTEGRATIONS_DIR", integrations_dir)

    # Path is inside sandbox but the file isn't there.
    copied = await apply_change(
        change_id="ch-missing-test",
        sandbox_dir=str(sandbox),
        generated_files=[str(sandbox / "never-created.py")],
    )

    assert copied == []
