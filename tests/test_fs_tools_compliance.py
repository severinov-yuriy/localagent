""": файловые инструменты и их контракты (кодировки, EOL, артефакты, trash)."""
from __future__ import annotations

import pytest

from localagent.runner import build_tools


# ---------- roundtrip ----------

def test_write_read_edit_undo_roundtrip(workspace, cfg):
    t = build_tools(cfg)
    t["write_file"].run({"path": "a.txt", "content": "hello"})
    assert t["read_file"].run({"path": "a.txt"}).endswith("hello")
    t["edit_file"].run({"path": "a.txt", "old": "hello", "new": "world"})
    assert "world" in t["read_file"].run({"path": "a.txt"})
    t["undo"].run({"path": "a.txt"})
    assert "hello" in t["read_file"].run({"path": "a.txt"})


def test_edit_requires_exactly_one_match(workspace, cfg):
    t = build_tools(cfg)
    t["write_file"].run({"path": "a.txt", "content": "xx"})
    with pytest.raises(ValueError):
        t["edit_file"].run({"path": "a.txt", "old": "x", "new": "y"})


def test_edit_zero_matches_raises(workspace, cfg):
    t = build_tools(cfg)
    t["write_file"].run({"path": "a.txt", "content": "abc"})
    with pytest.raises(ValueError):
        t["edit_file"].run({"path": "a.txt", "old": "zzz", "new": "y"})


def test_edit_replace_all(workspace, cfg):
    t = build_tools(cfg)
    t["write_file"].run({"path": "a.txt", "content": "x x x"})
    t["edit_file"].run({"path": "a.txt", "old": "x", "new": "y", "replace_all": True})
    assert "y y y" in t["read_file"].run({"path": "a.txt"})


def test_edit_preserves_crlf(workspace, cfg):
    """ENV-2 / : сохранение существующих EOL."""
    p = workspace / "a.txt"
    p.write_bytes(b"line1\r\nline2\r\n")
    t = build_tools(cfg)
    t["edit_file"].run({"path": "a.txt", "old": "line2", "new": "LINE2"})
    assert p.read_bytes() == b"line1\r\nLINE2\r\n"


def test_read_binary_is_rejected(workspace, cfg):
    (workspace / "b.bin").write_bytes(b"\x00\x01\x02\x03")
    t = build_tools(cfg)
    with pytest.raises(ValueError):
        t["read_file"].run({"path": "b.bin"})


def test_read_cp1251_fallback(workspace, cfg):
    (workspace / "r.txt").write_bytes("привет".encode("cp1251"))
    t = build_tools(cfg)
    out = t["read_file"].run({"path": "r.txt"})
    assert "привет" in out


def test_read_size_limit_enforced(workspace, cfg):
    cfg["permissions"]["max_read_bytes"] = 3
    (workspace / "x.txt").write_text("1234", encoding="utf-8")
    t = build_tools(cfg)
    with pytest.raises(ValueError):
        t["read_file"].run({"path": "x.txt"})


def test_read_line_range(workspace, cfg):
    (workspace / "x.txt").write_text("l1\nl2\nl3\nl4\n", encoding="utf-8")
    t = build_tools(cfg)
    r = t["read_file"].run({"path": "x.txt", "start_line": 2, "end_line": 3})
    assert "l2" in r and "l3" in r and "l1" not in r


def test_apply_patch_applies(workspace, cfg):
    (workspace / "a.txt").write_text("a\nb\nc\n", encoding="utf-8")
    patch = ("--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n")
    build_tools(cfg)["apply_patch"].run({"patch": patch})
    assert (workspace / "a.txt").read_text(encoding="utf-8") == "a\nB\nc\n"


def test_apply_patch_rejects_context_mismatch(workspace, cfg):
    (workspace / "a.txt").write_text("a\nb\n", encoding="utf-8")
    bad = "--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,2 @@\n-X\n+Y\n b\n"
    with pytest.raises(ValueError):
        build_tools(cfg)["apply_patch"].run({"patch": bad})


def test_glob_only_files_inside_workspace(workspace, cfg):
    (workspace / "a.py").write_text("x")
    (workspace / "sub").mkdir()
    (workspace / "sub" / "b.py").write_text("y")
    out = build_tools(cfg)["glob"].run({"path": ".", "pattern": "**/*.py"})
    lines = out.splitlines() if isinstance(out, str) else list(out)
    joined = "\n".join(str(x) for x in lines)
    assert "a.py" in joined and "sub/b.py" in joined


def test_grep_is_case_insensitive_and_reports_line(workspace, cfg):
    (workspace / "a.txt").write_text("HELLO world\n", encoding="utf-8")
    out = build_tools(cfg)["grep"].run({"pattern": "hello"})
    assert "a.txt:1:" in out and "HELLO" in out


def test_move_within_workspace(workspace, cfg):
    (workspace / "a.txt").write_text("x")
    build_tools(cfg)["move"].run({"src": "a.txt", "dst": "b.txt"})
    assert not (workspace / "a.txt").exists()
    assert (workspace / "b.txt").read_text() == "x"


def test_delete_disabled_by_default(workspace, cfg):
    (workspace / "a.txt").write_text("x")
    with pytest.raises(PermissionError):
        build_tools(cfg)["delete"].run({"path": "a.txt"})
    assert (workspace / "a.txt").exists()


def test_delete_moves_to_trash(workspace, cfg):
    """: delete — перемещение в .agent/trash/<session>/."""
    cfg["permissions"]["allow_delete"] = True
    (workspace / "a.txt").write_text("x")
    build_tools(cfg)["delete"].run({"path": "a.txt"})
    assert not (workspace / "a.txt").exists()
    trashed = list((workspace / ".agent" / "trash").rglob("a.txt"))
    assert trashed, "файл должен быть в .agent/trash/<session>/"


def test_view_image_returns_data_url(workspace, cfg):
    (workspace / "img.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)
    r = build_tools(cfg)["view_image"].run({"path": "img.png"})
    assert r["mime"] == "image/png"
    assert r["data_url"].startswith("data:image/png;base64,")


def test_read_secret_content_is_blocked_before_artifact_creation(workspace, cfg):
    (workspace / "report.txt").write_text("api_key=ABCDEFGHIJKLMNOPQRSTUV", encoding="utf-8")
    with pytest.raises(PermissionError, match="content blocked by security policy"):
        build_tools(cfg)["read_file"].run({"path": "report.txt"})
    assert not list((workspace / ".agent" / "artifacts").rglob("*.txt"))


def test_view_image_secret_payload_is_blocked(workspace, cfg):
    (workspace / "secret.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"password=synthetic-secret-value")
    with pytest.raises(PermissionError, match="content blocked by security policy"):
        build_tools(cfg)["view_image"].run({"path": "secret.png"})



# ----------  артефакты длинного вывода ----------

def test_long_tool_output_saved_to_artifacts(workspace, cfg):
    (workspace / "big.txt").write_text("A" * 30000, encoding="utf-8")
    cfg["permissions"]["max_read_bytes"] = 100000
    t = build_tools(cfg)
    out = t["read_file"].run({"path": "big.txt"})
    assert "truncated" in out.lower() or "обрезано" in out.lower()
    arts = list((workspace / ".agent" / "artifacts").rglob("*"))
    assert arts, "полный вывод должен быть в .agent/artifacts/<session>/"


def test_write_outside_workspace_rejected(workspace, cfg, tmp_path):
    with pytest.raises(PermissionError):
        build_tools(cfg)["write_file"].run(
            {"path": str(tmp_path / "out.txt"), "content": "x"}
        )
