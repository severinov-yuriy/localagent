"""Skills and knowledge-base behavior."""
from __future__ import annotations

import pytest

from localagent.knowledge import KnowledgeBase
from localagent.runner import build_tools
from localagent.tools.base import validate_tool_arguments


# ---------- skills ----------

def test_read_skill(workspace, cfg):
    (workspace / "skills" / "python").mkdir(parents=True, exist_ok=True)
    (workspace / "skills" / "python" / "SKILL.md").write_text("BODY", encoding="utf-8")
    assert build_tools(cfg)["read_skill"].run({"name": "python"}) == "BODY"


def test_read_skill_blocks_traversal(workspace, cfg):
    (workspace / "skills" / "python").mkdir(parents=True, exist_ok=True)
    (workspace / "skills" / "python" / "SKILL.md").write_text("x", encoding="utf-8")
    with pytest.raises(Exception):
        build_tools(cfg)["read_skill"].run({"name": "../../secret"})


def test_skill_frontmatter_parsed_or_tolerated(workspace, cfg):
    """The skill parser tolerates files without front matter."""
    sd = workspace / "skills" / "no_fm"
    sd.mkdir(parents=True)
    (sd / "SKILL.md").write_text("# Title\nBody\n", encoding="utf-8")
    assert build_tools(cfg)["read_skill"].run({"name": "no_fm"}).startswith("# Title")


# ---------- knowledge base ----------

def test_kb_add_and_search(workspace):
    kb = KnowledgeBase(workspace / "kb.sqlite")
    (workspace / "x.md").write_text("Spark GBT classifier with SHAP", encoding="utf-8")
    kb.add(workspace / "x.md")
    results = kb.search("Spark")
    assert results and results[0]["path"].endswith("x.md")


def test_kb_search_empty(workspace):
    kb = KnowledgeBase(workspace / "kb.sqlite")
    assert kb.search("nothing-here") == []


def test_kb_tools_roundtrip(workspace, cfg):
    (workspace / "x.md").write_text("tariff optimizer", encoding="utf-8")
    t = build_tools(cfg)
    t["kb_add"].run({"path": "x.md"})
    hits = t["kb_search"].run({"query": "tariff"})
    assert hits


def test_kb_add_rejects_path_outside_roots(workspace, cfg, tmp_path):
    """Agent knowledge-base writes remain policy-controlled."""
    outside = tmp_path / "outside.md"
    outside.write_text("x", encoding="utf-8")
    t = build_tools(cfg)
    with pytest.raises(Exception):
        t["kb_add"].run({"path": str(outside)})


def test_kb_incremental_index(workspace):
    """Repeated indexing of an unchanged document remains queryable."""
    kb = KnowledgeBase(workspace / "kb.sqlite")
    f = workspace / "x.md"
    f.write_text("v1", encoding="utf-8")
    kb.add(f)
    r1 = kb.search("v1")
    assert r1
    r2 = kb.search("v1")   # без изменений
    assert r2




def test_kb_add_argument_contract(workspace, cfg):
    t = build_tools(cfg)
    t["kb_add"].run({"path": "inline-note.md", "content": "inline searchable content"})
    t["kb_add"].run({"content": "content-only searchable"})
    (workspace / "source.md").write_text("path-only searchable", encoding="utf-8")
    t["kb_add"].run({"path": "source.md"})
    hits = t["kb_search"].run({"query": "searchable"})
    assert any(hit["path"] == "inline-note.md" for hit in hits)
    assert any(hit["path"].startswith("inline/") for hit in t["kb_search"].run({"query": "content-only"}))
    with pytest.raises(ValueError, match="requires path or content"):
        t["kb_add"].run({})


def test_kb_add_source_secret_is_blocked_before_persistence(workspace, cfg):
    source = workspace / "plain.txt"
    secret = "password=synthetic-secret-value"
    source.write_text(secret, encoding="utf-8")
    tool = build_tools(cfg)["kb_add"]
    with pytest.raises(PermissionError, match="content blocked by security policy"):
        tool.run({"path": "plain.txt"})
    rows = tool.kb.read("plain.txt")
    assert rows is None


def test_kb_add_schema_matches_runtime_contract(workspace, cfg):
    schema = build_tools(cfg)["kb_add"].schema()["function"]["parameters"]
    assert "anyOf" in schema
    validate_tool_arguments("kb_add", {"path": "doc.md", "content": "inline"})
    with pytest.raises(ValueError):
        validate_tool_arguments("kb_add", {})

