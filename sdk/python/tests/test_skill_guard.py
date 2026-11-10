# Copyright (c) Microsoft. All rights reserved.

"""The skill-guard example runs as written. The page's Python block
(docs-site/docs/examples/skill-guard.md) is executed and driven through
an emitter built from a host declaration, so the page and the behaviour
it documents cannot drift apart.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import json
import pathlib
import re
import time
from collections.abc import Mapping
from typing import Any

import pytest
from agent_hooks import (
    SPEC_VERSION_0_1,
    AgentContextBuilder,
    ApprovalOutcome,
    ApprovalRequest,
    ApprovalResolution,
    BindingContext,
    Decision,
    DeclarationError,
    DeclarationErrorClass,
    HostRegistry,
    HostSurface,
    InterceptionBlocked,
    InterceptionEmitter,
    InterceptionRecord,
    Transform,
    Verdict,
)

_ROOT = pathlib.Path(__file__).resolve().parents[3]
_PAGE = _ROOT / "docs-site" / "docs" / "examples" / "skill-guard.md"

# Skipped only where the repository's docs-site is absent (a packaged copy
# of the tests). In a full checkout a renamed or missing page fails.
pytestmark = pytest.mark.skipif(
    not (_ROOT / "docs-site").is_dir(), reason="repository docs-site not present"
)

KIND = "com.example.skill-guard"
DECLARATION_1_0 = "agent-hooks-declaration/1.0"
TOOL_POINTS = ("pre_tool_call", "post_tool_call")
MARKER = "pdftotext-extracts-the-text-layer"
CONTENT = f"# PDF tools\nRun {MARKER} on the file.\n"
PIN = "sha256:" + hashlib.sha256(CONTENT.encode("utf-8")).hexdigest()
CONFIG: dict[str, Any] = {
    "trusted_sources": ["internal-registry"],
    "allow": {"pdf-tools": PIN, "sql-helper": None},
    "block": ["shell-anything"],
    "max_bytes": 1024,
    "forbidden_patterns": ["curl | sh"],
}
_DEFAULT: Any = object()


def _blocks(lang: str) -> list[str]:
    text = _PAGE.read_text(encoding="utf-8")
    return re.findall(rf"```{lang}\n(.*?)```", text, flags=re.DOTALL)


@functools.cache
def _example() -> dict[str, Any]:
    """The page's guard, resolver and loader, executed as one module."""
    (source,) = [b for b in _blocks("python") if "class SkillGuard" in b]
    namespace: dict[str, Any] = {"__name__": "skill_guard_example"}
    exec(compile(source, str(_PAGE), "exec"), namespace)
    return namespace


@functools.cache
def _capabilities() -> list[str]:
    """The surface the page's own registry snippet declares."""
    (snippet,) = [b for b in _blocks("python") if "HostSurface.from_capabilities" in b]
    match = re.search(r"from_capabilities\(\s*\[(.*?)\]\s*\)", snippet, flags=re.DOTALL)
    assert match is not None
    return re.findall(r"\"([^\"]+)\"", match.group(1))


class Approver:
    """Scriptable approver. `transform` is an optional `$target` rewrite
    that an approving resolution carries (a permit verdict, §9)."""

    def __init__(self, outcome: ApprovalOutcome, transform: Transform | None = None) -> None:
        self.outcome = outcome
        self.transform = transform
        self.requests: list[ApprovalRequest] = []

    def resolve(self, request: ApprovalRequest) -> ApprovalResolution:
        self.requests.append(request)
        if self.outcome is ApprovalOutcome.APPROVE:
            verdict = (
                Verdict(decision=Decision.TRANSFORM, transform=self.transform)
                if self.transform is not None
                else Verdict.allow()
            )
        else:
            verdict = Verdict.deny(reason="skill_review:rejected")
        return ApprovalResolution(
            outcome=self.outcome, context_identity=request.context_identity, verdict=verdict
        )


class Reader:
    """A skill store that records every read."""

    def __init__(self, content: Any = CONTENT, error: BaseException | None = None) -> None:
        self.content = content
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def __call__(self, args: Mapping[str, Any]) -> Any:
        self.calls.append(dict(args))
        if self.error is not None:
            raise self.error
        return self.content


def _emitter(
    config: Any = _DEFAULT,
    *,
    approver: Approver | None = None,
    at: tuple[str, ...] = TOOL_POINTS,
    timeout_ms: int | None = None,
) -> InterceptionEmitter:
    registry = HostRegistry(HostSurface.from_capabilities(_capabilities())).kind(
        KIND, _example()["resolve_skill_guard"]
    )
    binding: dict[str, Any] = {
        "id": "skill-guard",
        "kind": KIND,
        "at": list(at),
        "config": CONFIG if config is _DEFAULT else config,
    }
    if timeout_ms is not None:
        binding["timeout_ms"] = timeout_ms
    document: dict[str, Any] = {
        "declaration": DECLARATION_1_0,
        "spec": SPEC_VERSION_0_1,
        "bindings": [binding],
    }
    if approver is not None:
        registry = registry.approval_resolver("skill-review", approver)
        document["configuration"] = {"approval": {"resolver": "skill-review"}}
    return InterceptionEmitter.from_declaration_value(document, registry)


def _builder() -> AgentContextBuilder:
    return AgentContextBuilder(
        spec=SPEC_VERSION_0_1, agent_id="agent-1", framework="example", session_id="session-1"
    )


def _load(
    emitter: InterceptionEmitter,
    reader: Reader,
    *,
    name: Any = "pdf-tools",
    source: Any = "internal-registry",
) -> Any:
    load_skill = _example()["load_skill"]
    return asyncio.run(
        load_skill(
            emitter, _builder(), reader, call_id="tc-1", name=name, source=source, version="1.0.0"
        )
    )


def _blocked(emitter: InterceptionEmitter, reader: Reader, **kw: Any) -> InterceptionRecord:
    with pytest.raises(InterceptionBlocked) as info:
        _load(emitter, reader, **kw)
    return info.value.result


def _points(emitter: InterceptionEmitter) -> list[str]:
    return [r.interception_point.value for r in emitter.results]


def _subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            k in actual and _subset(v, actual[k]) for k, v in expected.items()
        )
    return bool(expected == actual)


def test_the_page_declaration_loads_with_the_page_registry() -> None:
    (document,) = [b for b in _blocks("json") if '"bindings":' in b]
    (snippet,) = [b for b in _blocks("python") if "HostSurface.from_capabilities" in b]
    kinds = re.findall(r"\.kind\(\s*\"([^\"]+)\"", snippet)
    resolvers = re.findall(r"\.approval_resolver\(\s*\"([^\"]+)\"", snippet)
    assert sorted(kinds) == sorted(b["kind"] for b in json.loads(document)["bindings"])

    ex = _example()

    def allow_all(_config: Any, _binding: BindingContext) -> Any:
        return ex["AllowAll"]()

    registry = HostRegistry(HostSurface.from_capabilities(_capabilities()))
    for kind in kinds:
        registry = registry.kind(kind, ex["resolve_skill_guard"] if kind == KIND else allow_all)
    for name in resolvers:
        registry = registry.approval_resolver(name, Approver(ApprovalOutcome.APPROVE))

    em = InterceptionEmitter.from_declaration_json(document, registry)
    resolved = em.declaration
    assert resolved is not None
    (guard,) = [b for b in resolved.to_wire()["bindings"] if b["kind"] == KIND]
    assert sorted(guard["at"]) == sorted(TOOL_POINTS)

    # An agent that loads skills calls a model, and every point it emits
    # needs a binding in enforce mode: the page's passthrough covers them.
    builder = _builder()
    contexts = [
        builder.agent_startup(tools_registered=["load_skill"]),
        builder.input(content="hello", role="user"),
        builder.pre_model_call(model_id="m-1", messages=[{"role": "user", "content": "hello"}]),
        builder.post_model_call(model_id="m-1", content="hi", tool_calls=[], finish_reason="stop"),
        builder.output(content="hi"),
        builder.agent_shutdown(reason="completed"),
    ]
    for ctx in contexts:
        record = asyncio.run(em.emit_unchecked(ctx))
        assert record.verdict.decision is Decision.ALLOW, ctx["interception_point"]


def test_a_reviewed_skill_with_its_pinned_content_loads() -> None:
    em, reader = _emitter(), Reader()
    assert _load(em, reader) == CONTENT
    assert _points(em) == list(TOOL_POINTS)
    assert all(r.verdict.decision is Decision.ALLOW for r in em.results)
    assert reader.calls == [
        {"name": "pdf-tools", "source": "internal-registry", "version": "1.0.0"}
    ]


@pytest.mark.parametrize("approver", [False, True], ids=["no-approver", "with-approver"])
@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"name": "shell-anything"}, "skill_guard:blocked"),
        ({"source": "pastebin"}, "skill_guard:untrusted_source"),
        ({"source": None}, "skill_guard:untrusted_source"),
        ({"source": ["internal-registry"]}, "skill_guard:untrusted_source"),
        ({"name": "Shell-Anything"}, "skill_guard:invalid_name"),
        ({"name": "shell-anything "}, "skill_guard:invalid_name"),
        ({"name": ""}, "skill_guard:invalid_name"),
        ({"name": "../etc/passwd"}, "skill_guard:invalid_name"),
        ({"name": "a" * 65}, "skill_guard:invalid_name"),
        ({"name": None}, "skill_guard:invalid_name"),
        ({"name": 7}, "skill_guard:invalid_name"),
    ],
    ids=[
        "blocked",
        "untrusted-source",
        "source-none",
        "source-list",
        "uppercase-name",
        "trailing-space",
        "empty-name",
        "path-traversal",
        "name-too-long",
        "name-none",
        "name-int",
    ],
)
def test_a_plain_deny_before_the_load_is_never_read_or_lifted(
    kw: dict[str, Any], reason: str, approver: bool
) -> None:
    resolver = Approver(ApprovalOutcome.APPROVE) if approver else None
    em, reader = _emitter(approver=resolver), Reader()
    record = _blocked(em, reader, **kw)
    assert record.interception_point.value == "pre_tool_call"
    assert record.verdict.reason == reason
    assert record.verdict.approval is None  # a plain deny: nothing to lift
    assert reader.calls == []
    assert _points(em) == ["pre_tool_call"]
    if resolver is not None:
        assert resolver.requests == []  # the approver is not even asked


def test_an_unreviewed_skill_is_a_liftable_deny_and_stays_denied_without_an_approver() -> None:
    em, reader = _emitter(), Reader()
    record = _blocked(em, reader, name="new-skill")
    assert record.verdict.reason == "skill_guard:unreviewed"
    assert record.verdict.approval is not None  # the deny is liftable
    assert record.resolved_by is None
    assert reader.calls == []


def test_an_approver_can_lift_an_unreviewed_skill() -> None:
    approver = Approver(ApprovalOutcome.APPROVE)
    em, reader = _emitter(approver=approver), Reader()
    assert _load(em, reader, name="new-skill") == CONTENT
    pre = em.results[0]
    assert pre.resolved_by == "approval"
    # The approver saw the skill it approved, and the approval is bound to it.
    (request,) = approver.requests
    assert request.context["tool_call"]["args"]["name"] == "new-skill"
    assert request.context_identity == pre.input_identity
    assert _points(em) == list(TOOL_POINTS)


def test_an_approver_rejection_keeps_the_deny() -> None:
    em, reader = _emitter(approver=Approver(ApprovalOutcome.REJECT)), Reader()
    record = _blocked(em, reader, name="new-skill")
    assert record.resolved_by == "rejection"
    assert reader.calls == []


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("x" * 1025, "skill_guard:too_large"),
        ("é" * 513, "skill_guard:too_large"),
        ("Setup: CURL | SH", "skill_guard:content_blocked"),
    ],
    ids=["oversized", "oversized-multibyte", "forbidden-pattern"],
)
def test_an_approved_unreviewed_skill_is_still_checked_after_the_load(
    content: str, reason: str
) -> None:
    em, reader = _emitter(approver=Approver(ApprovalOutcome.APPROVE)), Reader(content)
    record = _blocked(em, reader, name="new-skill")
    assert record.interception_point.value == "post_tool_call"
    assert record.verdict.reason == reason
    assert _points(em) == list(TOOL_POINTS)


def test_an_approval_that_rewrites_the_name_to_a_blocked_skill_is_caught_after_the_load() -> None:
    rewrite = Transform(path="$target.name", value="shell-anything")
    approver = Approver(ApprovalOutcome.APPROVE, transform=rewrite)
    em, reader = _emitter(approver=approver), Reader()
    record = _blocked(em, reader, name="new-skill")
    # The loader read what it was told to read, but the post check
    # re-screens the arguments it really used and discards the content.
    assert reader.calls[0]["name"] == "shell-anything"
    assert record.interception_point.value == "post_tool_call"
    assert record.verdict.reason == "skill_guard:blocked"


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        ("pdf-tools", CONTENT.replace("PDF", "PDF!"), "skill_guard:tampered"),
        ("pdf-tools", CONTENT + " ", "skill_guard:tampered"),
        ("sql-helper", "x" * 1025, "skill_guard:too_large"),
        ("sql-helper", "é" * 513, "skill_guard:too_large"),
        ("sql-helper", "Setup: CURL | SH", "skill_guard:content_blocked"),
        ("sql-helper", "x" * 1024, None),
        ("sql-helper", "é" * 512, None),
        ("sql-helper", "", None),
        ("sql-helper", "any other reviewed text", None),
        ("pdf-tools", CONTENT, None),
    ],
    ids=[
        "tampered",
        "tampered-trailing-space",
        "oversized",
        "oversized-multibyte",
        "forbidden-pattern",
        "at-the-limit",
        "multibyte-at-the-limit",
        "empty",
        "unpinned-any-content",
        "pinned-exact-content",
    ],
)
def test_the_content_checks_after_the_load(name: str, content: str, reason: str | None) -> None:
    em, reader = _emitter(), Reader(content)
    if reason is None:
        assert _load(em, reader, name=name) == content
        return
    record = _blocked(em, reader, name=name)
    assert record.interception_point.value == "post_tool_call"
    assert record.verdict.reason == reason
    assert len(reader.calls) == 1  # read, then discarded


# bytes is absent on purpose: the SDK cannot serialise it into a context at
# all, which is why the loader turns it into a failed read first (below).
@pytest.mark.parametrize(
    "value", [None, ["a"], {"steps": []}, 7], ids=["none", "list", "dict", "int"]
)
def test_the_guard_denies_content_that_is_not_text(value: Any) -> None:
    em = _emitter()
    ctx = _builder().post_tool_call(
        call_id="tc-1",
        name="load_skill",
        args={"name": "sql-helper", "source": "internal-registry", "version": "1"},
        value=value,
    )
    record = asyncio.run(em.emit_unchecked(ctx))
    assert record.verdict.reason == "skill_guard:malformed"


@pytest.mark.parametrize(
    "content",
    [None, ["a"], {"steps": []}, 7, b"bytes"],
    ids=["none", "list", "dict", "int", "bytes"],
)
def test_the_loader_reports_content_that_is_not_text_as_a_failed_read(content: Any) -> None:
    em, reader = _emitter(), Reader(content)
    with pytest.raises(LookupError):
        _load(em, reader, name="sql-helper")
    assert _points(em) == list(TOOL_POINTS)
    assert em.results[1].verdict.decision is Decision.ALLOW


@pytest.mark.parametrize("point", TOOL_POINTS)
@pytest.mark.parametrize("is_error", [False, True], ids=["ok-result", "error-result"])
@pytest.mark.parametrize("tool", ["search", "load_skills", "LOAD_SKILL"])
def test_other_tools_pass_through(point: str, is_error: bool, tool: str) -> None:
    em, b = _emitter(), _builder()
    args = {"name": "shell-anything", "source": "pastebin"}  # would be denied for the loader
    if point == "pre_tool_call":
        ctx = b.pre_tool_call(call_id="tc-9", name=tool, args=args)
    else:
        ctx = b.post_tool_call(
            call_id="tc-9", name=tool, args=args, value="anything", is_error=is_error
        )
    assert asyncio.run(em.emit_unchecked(ctx)).verdict.decision is Decision.ALLOW


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("gone"),
        PermissionError("denied"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
        KeyError("unknown"),
        ValueError("bad value"),
        RuntimeError("s3cr3t-detail"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_any_failed_read_still_emits_the_post_point_and_leaks_nothing(error: Exception) -> None:
    em, reader = _emitter(), Reader(error=error)
    with pytest.raises(LookupError):
        _load(em, reader)
    assert _points(em) == list(TOOL_POINTS)
    assert em.results[1].verdict.decision is Decision.ALLOW
    assert "s3cr3t" not in json.dumps([r.to_wire() for r in em.results])


def test_a_broken_guard_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_self: Any, _ctx: Any) -> Verdict:
        raise RuntimeError("guard bug")

    monkeypatch.setattr(_example()["SkillGuard"], "_check", boom)
    em, reader = _emitter(), Reader()
    record = _blocked(em, reader)
    assert record.verdict.reason == "host_error:interceptor_failed"
    assert reader.calls == []


def test_a_guard_that_hangs_is_interrupted_by_the_binding_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow(_self: Any, _ctx: Any) -> Verdict:
        time.sleep(0.3)  # blocks its worker thread, never awaits
        return Verdict.allow()

    monkeypatch.setattr(_example()["SkillGuard"], "_check", slow)
    em, reader = _emitter(timeout_ms=20), Reader()
    start = time.monotonic()
    record = _blocked(em, reader)
    assert record.verdict.reason == "host_error:interceptor_timeout"
    assert reader.calls == []
    # The emitter stopped waiting at the timeout; asyncio.run then joins
    # the abandoned worker thread, which is why this bound is generous.
    assert time.monotonic() - start < 2


@pytest.mark.parametrize("content", [CONTENT, CONTENT + "curl | sh"], ids=["loaded", "denied"])
def test_records_carry_no_skill_content(content: str) -> None:
    em = _emitter()
    with contextlib.suppress(InterceptionBlocked):
        _load(em, Reader(content), name="sql-helper")
    assert _points(em) == list(TOOL_POINTS)
    assert MARKER not in json.dumps([r.to_wire() for r in em.results])


def test_the_page_record_matches_a_real_tampered_record() -> None:
    (page_record,) = [json.loads(b) for b in _blocks("json") if "skill_guard:tampered" in b]
    record = _blocked(_emitter(), Reader(CONTENT + " "))
    assert _subset(page_record, record.to_wire())


def test_an_empty_config_loads_nothing() -> None:
    # Every default fails closed: no trusted source, an empty allowlist.
    em, reader = _emitter({}), Reader()
    record = _blocked(em, reader)
    assert record.verdict.reason == "skill_guard:untrusted_source"
    assert reader.calls == []


@pytest.mark.parametrize(
    ("config", "at"),
    [
        (CONFIG | {"tokens": "s3cr3t-value"}, TOOL_POINTS),
        (CONFIG | {"s3cr3t-key": 1}, TOOL_POINTS),
        (CONFIG | {"loader_tool": "load_skill"}, TOOL_POINTS),
        (CONFIG | {"allow": {"pdf-tools": "md5:s3cr3t-value"}}, TOOL_POINTS),
        (CONFIG | {"allow": {"pdf-tools": "sha256:" + "A" * 64}}, TOOL_POINTS),
        (CONFIG | {"allow": {"pdf-tools": "sha256:" + "a" * 63}}, TOOL_POINTS),
        (CONFIG | {"allow": {"": None}}, TOOL_POINTS),
        (CONFIG | {"allow": {"Pdf-Tools": None}}, TOOL_POINTS),
        (CONFIG | {"allow": ["pdf-tools"]}, TOOL_POINTS),
        (CONFIG | {"block": [1]}, TOOL_POINTS),
        (CONFIG | {"block": ["Shell-Anything"]}, TOOL_POINTS),
        (CONFIG | {"block": ["pdf-tools"]}, TOOL_POINTS),
        (CONFIG | {"trusted_sources": "s3cr3t-value"}, TOOL_POINTS),
        (CONFIG | {"trusted_sources": [""]}, TOOL_POINTS),
        (CONFIG | {"forbidden_patterns": [""]}, TOOL_POINTS),
        (CONFIG | {"forbidden_patterns": "s3cr3t-value"}, TOOL_POINTS),
        (CONFIG | {"max_bytes": 0}, TOOL_POINTS),
        (CONFIG | {"max_bytes": -1}, TOOL_POINTS),
        (CONFIG | {"max_bytes": True}, TOOL_POINTS),
        (CONFIG | {"max_bytes": 1.5}, TOOL_POINTS),
        (CONFIG | {"max_bytes": "1024"}, TOOL_POINTS),
        (CONFIG | {"max_bytes": 1_048_577}, TOOL_POINTS),
        ([], TOOL_POINTS),
        ("s3cr3t-value", TOOL_POINTS),
        (CONFIG, ("pre_tool_call",)),
        (CONFIG, ("post_tool_call",)),
        (CONFIG, ("input", "pre_tool_call", "post_tool_call")),
        (CONFIG, ("input", "pre_tool_call")),
    ],
    ids=[
        "unknown-key-value",
        "unknown-key-name",
        "loader-tool-key",
        "pin-wrong-algorithm",
        "pin-uppercase-hex",
        "pin-short",
        "allow-empty-name",
        "allow-uppercase-name",
        "allow-not-an-object",
        "block-not-a-string",
        "block-uppercase-name",
        "block-and-allow",
        "trusted-sources-string",
        "trusted-sources-empty-entry",
        "pattern-empty",
        "patterns-string",
        "max-bytes-zero",
        "max-bytes-negative",
        "max-bytes-bool",
        "max-bytes-float",
        "max-bytes-string",
        "max-bytes-above-ceiling",
        "config-list",
        "config-string",
        "only-pre",
        "only-post",
        "extra-input-point",
        "pre-and-input",
    ],
)
def test_bad_config_or_points_refuse_the_document_without_echoing_it(
    config: Any, at: tuple[str, ...]
) -> None:
    with pytest.raises(DeclarationError) as info:
        _emitter(config, at=at)
    assert info.value.error_class is DeclarationErrorClass.BINDING_REJECTED
    assert "s3cr3t" not in str(info.value)
    assert all("s3cr3t" not in str(f) for f in info.value.findings)
