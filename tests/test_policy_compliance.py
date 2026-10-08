"""Path containment, deny precedence, extra read roots, symlinks, and write policy."""
from __future__ import annotations

from pathlib import Path

import pytest

from localagent.config import load_config
from localagent.policy import Policy, PolicyError, atomic_write


def _p(workspace, **overrides):
    c = load_config(str(workspace))
    for k, v in overrides.items():
        c["permissions"][k] = v
    return Policy(c)


def test_relative_path_resolves_inside_root(workspace):
    assert _p(workspace).path("a.txt") == workspace.resolve() / "a.txt"


@pytest.mark.parametrize("bad", ["../x", "../../etc/passwd"])
def test_dotdot_escape_rejected(workspace, bad):
    with pytest.raises(PolicyError):
        _p(workspace).path(bad)


def test_absolute_path_outside_rejected(workspace, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("no", encoding="utf-8")
    with pytest.raises(PolicyError):
        _p(workspace).path(str(outside))


@pytest.mark.parametrize("rel", [".env", "key.pem", ".agent/config.yaml",
                                 "AGENTS.md", "id_rsa", "sub/.env"])
def test_deny_paths_rejected(workspace, rel):
    p = _p(workspace)
    operation = "write" if rel == "AGENTS.md" else "read"
    with pytest.raises(PolicyError):
        p.authorize(rel, operation)


def test_deny_priority_over_allow(workspace):
    """Deny rules take precedence over allow rules."""
    c = load_config(str(workspace))
    c["permissions"]["write"] = ["**"]
    c["permissions"]["deny"] = ["secret.txt"]
    (workspace / "secret.txt").write_text("x", encoding="utf-8")
    p = Policy(c)
    with pytest.raises(PolicyError):
        p.path("secret.txt", write=True)


def test_allow_write_false_blocks_writes(workspace):
    with pytest.raises(PolicyError):
        _p(workspace, allow_write=False).path("a.txt", write=True)


def test_symlink_escape_rejected(workspace, tmp_path):
    target = tmp_path / "outside"
    target.mkdir(exist_ok=True)
    (target / "secret.txt").write_text("nope", encoding="utf-8")
    link = workspace / "link.txt"
    try:
        link.symlink_to(target / "secret.txt")
    except OSError:
        pytest.skip("symlinks not supported")
    with pytest.raises(PolicyError):
        _p(workspace).path("link.txt")


def test_allow_missing_defaults_true_but_allow_missing_false_rejects(workspace):
    p = _p(workspace)
    # позитивная ветка
    p.path("nope.txt")  # не должно падать
    # негативная ветка
    with pytest.raises(PolicyError):
        p.path("nope.txt", allow_missing=False)


def test_atomic_write_replaces_content(workspace):
    f = workspace / "a.txt"
    atomic_write(f, b"hello")
    atomic_write(f, b"world")
    assert f.read_bytes() == b"world"



def test_artifact_path_is_workspace_relative(workspace):
    artifact = _p(workspace).artifact("content")
    assert artifact.startswith(".agent/artifacts/")
    assert not Path(artifact).is_absolute()
