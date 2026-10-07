
import pytest

from localagent.agent import Agent
from localagent.config import load_config
from localagent.llm import LLMResponse, ToolCall, OpenAICompatClient
from localagent.policy import PolicyError
from localagent.runner import build_tools, load_role
from localagent.ui import UI


def cfg(tmp_path):
    c = load_config(tmp_path)
    c["permissions"]["confirm"] = "auto"
    return c


def test_allow_write_is_enforced(tmp_path):
    c = cfg(tmp_path)
    c["permissions"]["allow_write"] = False
    tools = build_tools(c)
    with pytest.raises(PolicyError):
        tools["write_file"].run({"path": "x.txt", "content": "no"})
    assert not (tmp_path / "x.txt").exists()


def test_role_path_traversal_is_rejected(tmp_path):
    root = tmp_path / "workspace"
    (root / "agents").mkdir(parents=True)
    (tmp_path / "secret.md").write_text("secret", encoding="utf-8")
    with pytest.raises(ValueError):
        load_role(root, "../../secret")


def test_pi_skill_is_available_but_path_traversal_is_not(tmp_path):
    root = tmp_path / ".pi" / "skills" / "demo"
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text("demo skill", encoding="utf-8")
    tools = build_tools(cfg(tmp_path))
    assert tools["read_skill"].run({"name": "demo"}) == "demo skill"
    with pytest.raises(FileNotFoundError):
        tools["read_skill"].run({"name": "../../secret"})


def test_exec_is_disabled_and_not_exposed_by_default(tmp_path):
    tools = build_tools(cfg(tmp_path))
    assert "run_python" not in tools
    assert "run_tests" not in tools
    assert "run_command" not in tools


def test_read_size_limit(tmp_path):
    c = cfg(tmp_path)
    c["permissions"]["max_read_bytes"] = 3
    (tmp_path / "x.txt").write_text("1234", encoding="utf-8")
    tools = build_tools(c)
    with pytest.raises(ValueError, match="max_read_bytes"):
        tools["read_file"].run({"path": "x.txt"})


def test_openrouter_profile_can_initialize_agent(tmp_path):
    c = cfg(tmp_path)
    client = OpenAICompatClient(c)
    agent = Agent(c, client, {}, UI(), model="deepseek/deepseek-chat-v3.1")
    assert agent.effort == "medium"
    assert agent._request_params()["max_tokens"] == 16_384
    client.close()


def test_openrouter_reasoning_format_uses_openrouter_payload(tmp_path):
    c = cfg(tmp_path)
    c["llm"]["reasoning_format"] = "openrouter"
    client = OpenAICompatClient(c)
    agent = Agent(c, client, {}, UI(), model="DeepSeek-V4-Flash-0731")
    params = agent._request_params()
    assert params["extra_body"] == {"reasoning": {"effort": "high"}}
    client.close()


def test_reasoning_effort_is_model_specific_and_sent_as_extra_body(tmp_path):
    c = cfg(tmp_path)
    c["permissions"]["confirm"] = "auto"
    client = OpenAICompatClient(c)
    agent = Agent(c, client, {}, UI(), model="DeepSeek-V4-Flash-0731")
    params = agent._request_params()
    assert agent.effort == "high"
    assert params["extra_body"] == {"chat_template_kwargs": {"reasoning_effort": "high"}}
    assert params["max_tokens"] == 131000

    agent_q = Agent(c, client, {}, UI(), model="Qwen3.8-Flash")
    params_q = agent_q._request_params()
    assert agent_q.effort == "medium"
    assert params_q["extra_body"] == {"chat_template_kwargs": {"reasoning_effort": "medium"}, "top_k": 20}
    client.close()


def test_agent_tool_loop_preserves_history_and_finishes(tmp_path):
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "coder.md").write_text("Do the task.", encoding="utf-8")
    (tmp_path / "x.txt").write_text("hello", encoding="utf-8")
    c = cfg(tmp_path)

    class FakeLLM:
        def __init__(self):
            self.requests = []
            self.responses = [
                LLMResponse(
                    text="",
                    tool_calls=[ToolCall(id="1", name="read_file", arguments='{"path":"x.txt"}')],
                    finish_reason="tool_calls",
                ),
                LLMResponse(text="done", finish_reason="stop"),
            ]

        def complete(self, request):
            self.requests.append(request.messages.copy())
            return self.responses.pop(0)

    fake = FakeLLM()
    ui = UI()
    agent = Agent(c, fake, build_tools(c), ui)
    assert agent.run("read the file")["summary"] == "done"
    assert len(fake.requests) == 2
    assert fake.requests[1][-1]["role"] == "tool"
    # second request uses the same extra_body shape; inspect the captured message list above
    assert fake.responses == []
    assert (tmp_path / ".agent/sessions" / f"{agent.session_id}.json").exists()


def test_agent_does_not_add_parent_agents_md_from_outside_workspace(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (tmp_path / "AGENTS.md").write_text("OUTSIDE", encoding="utf-8")
    (root / "AGENTS.md").write_text("INSIDE", encoding="utf-8")
    (root / "agents").mkdir()
    (root / "agents" / "coder.md").write_text("role", encoding="utf-8")
    c = cfg(root)
    class FakeLLM:
        def complete(self, request):
            assert "INSIDE" in request.messages[0]["content"]
            assert "OUTSIDE" not in request.messages[0]["content"]
            return LLMResponse(text="ok", finish_reason="stop")
    Agent(c, FakeLLM(), build_tools(c), UI()).run("test")
