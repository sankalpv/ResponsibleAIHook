# Example: check every skill before it loads

Agent Hooks has no skill-loading point, and a host cannot add one: the
eight points are closed (§3). It does not need one. Route every skill
load through one loader that the host treats as a tool, and the load is
bracketed by `pre_tool_call` and `post_tool_call` like any other tool
call. This is the same move [INTEROP.md](https://github.com/responsibleai/agent-hooks/blob/main/docs/INTEROP.md)
recommends for MCP resource reads.

The guard is one binding kind, bound at the two tool points:

- before the load it checks which skill and where it comes from;
- after the load it checks the same again, then what the skill contains.

Put the skill's name, source and version in the tool arguments, not in
`extensions`: the context identity covers `tool_call.args` and
`tool_result.value` (§10.2), so the record proves which skill was
checked. At `pre_tool_call` an approver sees and approves those three
arguments, not the content. An approved skill that has no digest pinned
in `allow` is still held to the size and pattern checks afterwards, but
any other content it serves loads. Pin a skill once it is reviewed.

## The guard, its kind resolver and the loader

```python
from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Callable, Mapping
from typing import Any

from agent_hooks import (
    AgentContextBuilder,
    BindingContext,
    InterceptionEmitter,
    InterceptionPoint,
    Verdict,
)

LOADER_TOOL = "load_skill"
TOOL_POINTS = frozenset({InterceptionPoint.PRE_TOOL_CALL, InterceptionPoint.POST_TOOL_CALL})
MAX_BYTES_CEILING = 1_048_576
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _slug(value: Any) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def _slugs(value: Any) -> bool:
    return isinstance(value, list) and all(_slug(v) for v in value)


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def _pins(value: Any) -> bool:
    return isinstance(value, Mapping) and all(
        _slug(name) and (pin is None or (isinstance(pin, str) and _DIGEST.fullmatch(pin)))
        for name, pin in value.items()
    )


# Every config key, its default and its check. The defaults fail
# closed: no trusted source and an empty allowlist load nothing.
_CONFIG: dict[str, tuple[Any, Callable[[Any], bool]]] = {
    "trusted_sources": ([], _strings),
    "allow": ({}, _pins),
    "block": ([], _slugs),
    "max_bytes": (262_144, lambda v: type(v) is int and 0 < v <= MAX_BYTES_CEILING),
    "forbidden_patterns": ([], _strings),
}


class SkillGuard:
    """Checks each skill the host loads through its loader tool."""

    def __init__(self, config: Mapping[str, Any]) -> None:
        self._trusted = frozenset(config["trusted_sources"])
        self._allow = dict(config["allow"])  # skill name -> pinned digest, or None
        self._block = frozenset(config["block"])
        self._max_bytes = config["max_bytes"]
        self._patterns = tuple(p.casefold() for p in config["forbidden_patterns"])

    async def intercept(self, ctx: Mapping[str, Any]) -> Verdict:
        # The checks run in a worker thread. The emitter's timeout can only
        # interrupt an interceptor at an await (§7), so a body that never
        # awaits would run to the end however long it took.
        return await asyncio.to_thread(self._check, ctx)

    def _check(self, ctx: Mapping[str, Any]) -> Verdict:
        call = ctx.get("tool_call") or {}
        if call.get("name") != LOADER_TOOL:
            return Verdict.allow()  # not a skill load
        args = call["args"]
        # At both points: at post, the arguments are the ones the loader
        # really used, after any rewrite by another control (§4.2).
        denied = self._screen(args)
        if denied is not None:
            return denied
        if ctx["interception_point"] == "pre_tool_call":
            if args["name"] not in self._allow:
                # A liftable deny: a registered approver may allow it (§9).
                return Verdict.escalate(
                    reason="skill_guard:unreviewed",
                    message=f"skill {args['name']!r} has not been reviewed",
                )
            return Verdict.allow()
        if ctx["interception_point"] == "post_tool_call":
            return self._after_load(args, ctx["tool_result"])
        return Verdict.allow()

    def _screen(self, args: Mapping[str, Any]) -> Verdict | None:
        name, source = args.get("name"), args.get("source")
        if not _slug(name):
            return Verdict.deny(reason="skill_guard:invalid_name", message="invalid skill name")
        if name in self._block:
            return Verdict.deny(reason="skill_guard:blocked", message=f"skill {name!r} is blocked")
        if not isinstance(source, str) or source not in self._trusted:
            return Verdict.deny(
                reason="skill_guard:untrusted_source",
                message=f"skill {name!r} is not from a trusted source",
            )
        return None

    def _after_load(self, args: Mapping[str, Any], result: Mapping[str, Any]) -> Verdict:
        if result["is_error"]:
            return Verdict.allow()  # nothing was loaded
        content = result["value"]
        if not isinstance(content, str):
            return Verdict.deny(reason="skill_guard:malformed", message="skill content is not text")
        body = content.encode("utf-8")
        if len(body) > self._max_bytes:
            return Verdict.deny(
                reason="skill_guard:too_large",
                message=f"skill is {len(body)} bytes; the limit is {self._max_bytes}",
            )
        pinned = self._allow.get(args["name"])
        if pinned is not None and "sha256:" + hashlib.sha256(body).hexdigest() != pinned:
            return Verdict.deny(
                reason="skill_guard:tampered",
                message="skill content does not match its pinned digest",
            )
        text = content.casefold()
        if any(p in text for p in self._patterns):
            return Verdict.deny(
                reason="skill_guard:content_blocked",
                message="skill content contains a forbidden pattern",
            )
        return Verdict.allow()


def resolve_skill_guard(config: Any, binding: BindingContext) -> SkillGuard:
    """Kind resolver: checks the binding once, at load (§7.7.5). A
    raise refuses the whole document as binding_rejected. Messages name
    keys, never values, because config may hold secrets."""
    where = f"binding {binding.id!r}"
    if binding.at != TOOL_POINTS:
        # Bound at one point only, the guard would silently skip the other half.
        raise ValueError(f"{where}: bind it at pre_tool_call and post_tool_call, both and only")
    if not isinstance(config, Mapping):
        raise ValueError(f"{where}: config must be an object")
    if not set(config) <= set(_CONFIG):
        raise ValueError(f"{where}: config may only have the keys {sorted(_CONFIG)}")
    merged = {key: config.get(key, default) for key, (default, _) in _CONFIG.items()}
    for key, (_, valid) in _CONFIG.items():
        if not valid(merged[key]):
            raise ValueError(f"{where}: config.{key} is invalid")
    if set(merged["block"]) & set(merged["allow"]):
        raise ValueError(f"{where}: a skill cannot be in both config.block and config.allow")
    return SkillGuard(merged)


class AllowAll:
    """The explicit passthrough for points with no other control (§7)."""

    def intercept(self, ctx: Mapping[str, Any]) -> Verdict:
        return Verdict.allow()


async def load_skill(
    emitter: InterceptionEmitter,
    builder: AgentContextBuilder,
    read_skill: Callable[[Mapping[str, Any]], str],
    *,
    call_id: str,
    name: str,
    source: str,
    version: str,
) -> str:
    """The only path a skill takes into the agent: model-requested,
    user-invoked and host-loaded skills alike. Raises
    InterceptionBlocked when a check denies, and LookupError when the
    skill cannot be read; the agent loop turns either into a tool
    error for the model (§6.2)."""
    args = {"name": name, "source": source, "version": version}
    pre = await emitter.emit(builder.pre_tool_call(call_id=call_id, name=LOADER_TOOL, args=args))
    args = pre.target  # the arguments as the checks allowed them
    try:
        content = await asyncio.to_thread(read_skill, args)
        if not isinstance(content, str):
            raise TypeError("skill content must be text")
        failed = False
    except Exception as e:  # noqa: BLE001 - any failed read is a tool error (§3)
        # Only the type name goes in the result: it reaches the model and the guard.
        content, failed = f"skill could not be read: {type(e).__name__}", True
    # Always emit the post point, so each pre_tool_call has its pair (§3.1).
    post = await emitter.emit(
        builder.post_tool_call(
            call_id=call_id, name=LOADER_TOOL, args=args, value=content, is_error=failed
        )
    )
    if failed:
        raise LookupError(f"skill {args['name']!r} could not be read")
    return post.target  # the content as the checks allowed it
```

## The binding

```json
{
  "declaration": "agent-hooks-declaration/1.0",
  "spec": "agent-hooks/0.1",
  "configuration": { "approval": { "resolver": "skill-review" } },
  "bindings": [
    {
      "id": "skill-guard",
      "kind": "com.example.skill-guard",
      "at": ["pre_tool_call", "post_tool_call"],
      "timeout_ms": 2000,
      "config": {
        "trusted_sources": ["internal-registry"],
        "allow": {
          "pdf-tools": "sha256:c01cbf61483372224776f06e1a95b77b65f9f7233e2979a07bd288cb4bfda078",
          "sql-helper": null
        },
        "block": ["shell-anything"],
        "max_bytes": 262144,
        "forbidden_patterns": ["curl | sh", "ignore previous instructions"]
      }
    },
    {
      "id": "passthrough",
      "kind": "com.example.allow-all",
      "at": [
        "agent_startup", "input", "pre_model_call", "post_model_call",
        "output", "agent_shutdown"
      ]
    }
  ]
}
```

`allow` maps each reviewed skill to the SHA-256 of its content, or to
`null` to allow any content that passes the other checks. Compute a pin
over the exact UTF-8 text `read_skill` returns; a file decoded with
different newline or BOM handling than the host uses will not match and
is denied as tampered. The passthrough binding is there because, in
`enforce` mode, a point with no binding denies every emission with
`host_error:no_interceptor` (§7.7.5), and an agent that loads skills
calls a model. A host with other controls binds those instead.

Register the kinds and the approver in code, then load the document:

```python
from agent_hooks import HostRegistry, HostSurface, InterceptionEmitter

registry = (
    HostRegistry(HostSurface.from_capabilities(["model_calls", "tool_calls", "host_declaration"]))
    .kind("com.example.skill-guard", resolve_skill_guard)
    .kind("com.example.allow-all", lambda config, binding: AllowAll())
    .approval_resolver("skill-review", SkillReviewQueue())
)
emitter = InterceptionEmitter.from_declaration_path("agent-hooks.declaration.json", registry)
```

`SkillReviewQueue` is your approver: any object with a `resolve`
method that returns an `ApprovalResolution` echoing the request's
`context_identity` (§9).

## What each check returns

| Point | Condition | Verdict |
| --- | --- | --- |
| either | the tool is not the loader | `allow` |
| either | the name is not a lowercase slug (`[a-z0-9][a-z0-9._-]{0,63}`) | `deny skill_guard:invalid_name` |
| either | the name is in `block` | `deny skill_guard:blocked` |
| either | the source is not in `trusted_sources` | `deny skill_guard:untrusted_source` |
| `pre_tool_call` | the name is not in `allow` | `deny skill_guard:unreviewed` with an `approval` block |
| `post_tool_call` | the read failed | `allow` (nothing was loaded) |
| `post_tool_call` | the content is not text | `deny skill_guard:malformed` |
| `post_tool_call` | the content exceeds `max_bytes` | `deny skill_guard:too_large` |
| `post_tool_call` | the content does not match its pinned digest | `deny skill_guard:tampered` |
| `post_tool_call` | the content contains a forbidden pattern | `deny skill_guard:content_blocked` |

The first four rows run at both points. At `post_tool_call` they look
at the arguments the loader actually used, so another control that
rewrites the name or source cannot swap in a blocked skill. The loader
reports content that is not text as a failed read, so `malformed` is a
second line of defence for a host that emits the post point itself.

A deny at `pre_tool_call` means the skill is never read. A deny at
`post_tool_call` means the host discards what it read (§6.1). If the
guard raises, times out or returns an invalid verdict, the emitter
denies with `host_error:*` (§6.3), so a broken guard never lets a skill
through. Names are matched exactly and are never normalised: anything
that is not a lowercase slug is denied, so `Shell-Anything` cannot
slip past a blocklist entry on a case-insensitive store.

## What the record shows

A tampered skill, abridged. The record names the skill through the
arguments' identity and carries no skill content (§10.3):

```json
{
  "interception_point": "post_tool_call",
  "verdict": {
    "decision": "deny",
    "reason": "skill_guard:tampered",
    "message": "skill content does not match its pinned digest"
  },
  "decided_by": 0,
  "declaration": "agent-hooks-declaration/1.0"
}
```

## Host duties

- Every skill enters the agent through `load_skill`. The contract does
  not promise complete mediation (§1.4); a second path that bypasses
  the loader bypasses the guard.
- Bound the read. The SDK does not enforce the recommended 5 MiB
  context bound (§12.3, TM-12), so have `read_skill` stop at
  `max_bytes + 1` bytes instead of loading a whole file before the
  guard sees it. The resolver caps `max_bytes` at 1 MiB.
- Under the default `sequential/first_deny` profile, lifting the
  guard's deny with an approval skips every control bound after it at
  that point. If other controls follow the guard, set
  `composition.on_approval` to `resume`.
- Load skills on first use, so each load happens inside a turn. A host
  that must preload skills still calls `load_skill` for each one, after
  `agent_startup` has been allowed. The resolver refuses any binding
  that is not on exactly the two tool points, so the guard is never
  bound where it would check nothing and allow everything.
- The forbidden patterns are a tripwire, not a filter: a substring is
  easily dodged (`curl|sh`, extra spaces, look-alike characters). Rely
  on pinned digests for skills that matter.

Per load, the guard encodes the content once, hashes it when a digest is
pinned, folds its case once, and scans it once per forbidden pattern. The
checks run in a worker thread, so the binding's `timeout_ms` applies; a
timed-out check is abandoned, not killed, which is why `max_bytes` stays
small. For a long pattern list, swap the `in` scan for a single
multi-pattern matcher such as Aho-Corasick to keep it to one pass.
