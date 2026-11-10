# ResponsibleAIHook: checking every skill an agent loads

This repository adds a **skill-load guard** to Microsoft's
[agent-hooks](https://github.com/responsibleai/agent-hooks), the open
interception contract between an agent host and the controls that govern
it. The guard runs checks on every skill an agent loads, using only the
hook contract that already exists. Nothing in the spec, the Rust core or
the SDK APIs changed.

> An interactive version of this page, with a clickable walk-through of
> each scenario, is in [docs/skill-guard-explainer.html](docs/skill-guard-explainer.html).
> GitHub shows HTML files as source, so download it and open it in a browser.
> The upstream project's own README is kept as [UPSTREAM-README.md](UPSTREAM-README.md).

## In one paragraph

agent-hooks has 8 fixed checkpoints, and a host may not invent a ninth.
So there is no "skill load" checkpoint. Instead, the host loads every
skill through one function, `load_skill`, which it reports as a tool call.
That puts each skill load between two checkpoints that already exist:
`pre_tool_call` (before the skill is read) and `post_tool_call` (after it
is read, before the agent sees it). A new binding kind,
`com.example.skill-guard`, sits at those two checkpoints and returns
allow or deny.

What was added:

| File | What it is |
| --- | --- |
| [docs-site/docs/examples/skill-guard.md](docs-site/docs/examples/skill-guard.md) | The guard, its kind resolver, the loader, the declaration and the verdict table |
| [sdk/python/tests/test_skill_guard.py](sdk/python/tests/test_skill_guard.py) | 102 test cases that run the page's code as written |
| [docs-site/mkdocs.yml](docs-site/mkdocs.yml) | One nav line for the new page |

## 1. The problem and the constraint

A **skill** is a packaged set of instructions (often a `SKILL.md` file)
that an agent pulls into its context when it needs it. That makes it a way
in for untrusted instructions. The gate should block a skill based on
*which* skill it is, *where* it came from, and *what* it contains.

- **Rejected: a new `skill_load` checkpoint.** The spec says (section 3)
  that the set of points is closed, so a ninth point would mean changing
  the spec, the schemas, all five SDKs, the conformance vectors and the
  declaration format.
- **Chosen: treat a skill load as a tool call.** `docs/INTEROP.md` already
  uses this approach for MCP resource reads. A tool call gets a *before*
  and an *after* checkpoint, which are exactly the two gates needed.

## 2. What happens on a skill load

1. The agent asks for a skill (the model, a user command, or the host).
2. `load_skill` emits `pre_tool_call` with the tool name `load_skill` and
   the arguments `{name, source, version}`.
3. **Gate 1, which skill and where from.** Valid name, then blocklist,
   then trusted source, then reviewed (allowlist).
4. A skill that is not on the allowlist gets a deny that a registered
   approver can lift. With no approver, it stays a deny.
5. The host reads the skill, only after gate 1 allows. A read error still
   emits step 6, as an error result.
6. `load_skill` emits `post_tool_call` with the skill text as the result.
7. **Gate 2, what the skill contains.** Re-check name and source, then
   text only, size limit, pinned SHA-256, forbidden patterns.
8. The skill enters the agent's context. This is the only way in. A deny
   at step 7 means the host throws the text away.

## 3. The pieces

Everything is in
[skill-guard.md](docs-site/docs/examples/skill-guard.md). It follows the
same pattern as every other control in agent-hooks: **binding, kind
resolver, interceptor, verdict**.

**The binding** (in the host's declaration file) says what to call, where,
and with what settings:

```json
{
  "id": "skill-guard",
  "kind": "com.example.skill-guard",
  "at": ["pre_tool_call", "post_tool_call"],
  "timeout_ms": 2000,
  "config": {
    "trusted_sources": ["internal-registry"],
    "allow": { "pdf-tools": "sha256:c01c…a078", "sql-helper": null },
    "block": ["shell-anything"],
    "max_bytes": 262144,
    "forbidden_patterns": ["curl | sh", "ignore previous instructions"]
  }
}
```

`allow` pins each reviewed skill to the SHA-256 of its content; `null`
means any content that passes the other checks. An explicit allow-all
binding covers the other checkpoints, including the two model ones,
because in enforce mode a checkpoint with nothing bound denies everything
(`host_error:no_interceptor`).

**The kind resolver** (`resolve_skill_guard`) runs once, when the
declaration loads. It checks every config key and refuses anything it does
not understand, which rejects the whole file before any agent runs. Its
messages name keys, never values, because config can hold secrets. It also
refuses any binding that is not on exactly both tool checkpoints, since
bound at only one, half the guard would silently do nothing.

**The interceptor** (`SkillGuard.intercept`) ignores every tool that is not
`load_skill`. Its checks run in a worker thread so the SDK's timeout can
fire; that timeout can only interrupt an interceptor at an `await`.

**The host gateway** (`load_skill`) is the single route every skill takes
into the agent. It always emits *both* checkpoints, even when the read
fails, because each `pre_tool_call` must have its matching
`post_tool_call` (spec section 3.1). A deny raises `InterceptionBlocked`; a
failed read raises `LookupError`.

## 4. What the guard decides

| Checkpoint | If | Verdict |
| --- | --- | --- |
| either | the tool is not `load_skill` | allow |
| either | the name is not a lowercase slug (`[a-z0-9][a-z0-9._-]{0,63}`) | deny `skill_guard:invalid_name` |
| either | the name is on the blocklist | deny `skill_guard:blocked` |
| either | the source is not trusted | deny `skill_guard:untrusted_source` |
| `pre_tool_call` | the skill is not on the allowlist | liftable deny `skill_guard:unreviewed` |
| `post_tool_call` | the read itself failed | allow (nothing was loaded) |
| `post_tool_call` | the content is not text | deny `skill_guard:malformed` |
| `post_tool_call` | it is bigger than `max_bytes` | deny `skill_guard:too_large` |
| `post_tool_call` | its SHA-256 does not match the pin | deny `skill_guard:tampered` |
| `post_tool_call` | it contains a forbidden pattern | deny `skill_guard:content_blocked` |

The first four rows run at **both** checkpoints. At `post_tool_call` they
re-check the arguments the loader *actually used*, so another control or
an approver that rewrites the name or source cannot swap in a blocked
skill. Names are matched exactly and never normalised, so `Shell-Anything`
cannot slip past a blocklist entry on a case-insensitive store.

If the guard itself crashes, times out or returns garbage, the SDK turns
that into a deny (`host_error:interceptor_failed` and similar). A broken
guard never lets a skill through.

## 5. The contract rules the design relies on

| Rule (spec 0.1) | How the design uses it |
| --- | --- |
| Section 3: the checkpoint set is closed | Why the tool checkpoints are reused instead of adding one |
| Section 3.1: each pre has exactly one post | `load_skill` emits the post checkpoint even when the read fails |
| Sections 6.1 and 6.2: deny before vs after | A deny before means the skill is never read; a deny after means the text is discarded |
| Section 6.3: failures deny | Under 0.1 there is no knob: a crashed or hung guard always blocks |
| Section 7.7.5: resolvers validate and never echo config | Strict config checks; error messages name keys only |
| Section 9: approval echoes the fingerprint | The approver sees the exact skill arguments, and the approval is bound to them |
| Section 10.2: the fingerprint covers `tool_call.args` and `tool_result.value` | Skill name, source and version go in `args`, not in `extensions` |
| Section 10.3: records carry no payload | The audit record shows the verdict but never the skill text (a test checks this) |

## 6. How it is tested

`sdk/python/tests/test_skill_guard.py` does not keep its own copy of the
guard. It pulls the Python block out of the docs page and runs that exact
code through a real emitter built from a real declaration, so editing the
page in a way that breaks it fails the test.

102 test cases from 19 test functions:

| Test | Cases | What it proves |
| --- | --- | --- |
| page declaration loads with page registry | 1 | The JSON and registry code on the page load together, and every lifecycle and model point is allowed |
| reviewed skill loads | 1 | Happy path |
| plain deny before load | 22 | 11 bad names or sources, each with and without an approver: never read, never lifted, approver never asked |
| unreviewed: liftable, lifted, rejected | 3 | Approval block present; no approver means denied; approve loads; reject stays denied |
| approved skill is still checked after load | 3 | Oversized, multibyte-oversized and forbidden-pattern content is discarded even after approval |
| approver rewrites the name to a blocked skill | 1 | Caught at gate 2 |
| content checks after load | 10 | Tampered, trailing space, at and over the byte limit (ASCII and multibyte), forbidden pattern, empty, unpinned, pinned |
| guard denies non-text content | 4 | `malformed` |
| loader reports non-text as a failed read | 5 | `LookupError`, post still emitted |
| other tools pass through | 12 | Both checkpoints, ok and error results, three look-alike tool names |
| any failed read still emits post | 6 | Six exception types; nothing from the message reaches a record |
| broken guard fails closed; hung guard times out | 2 | `interceptor_failed`; `interceptor_timeout` with `timeout_ms` honoured |
| records carry no skill content | 2 | Loaded and denied |
| page record matches a real record; empty config loads nothing | 2 | The page's example is real; defaults fail closed |
| bad config or points refuse the document | 28 | Unknown keys, bad pins, names and limits, wrong types, block and allow overlap, one-point and extra-point bindings; no secret value is echoed |

## 7. What review and an end-to-end run found

A subagent reviewed the change, and a second ran the page's code as
written in a fake agent session with real skill files. The end-to-end run
confirmed every row of the original verdict table, so most findings were
gaps beyond it. The surprising ones were re-checked before anything was
changed.

| # | Finding | Fix |
| --- | --- | --- |
| 1 | A binding at only one tool point was accepted, silently disabling half the guard | Resolver requires exactly both points |
| 2 | A `loader_tool` config key (or a typo in it) turned the guard off | Key removed; the tool name is a constant |
| 3 | Only `OSError` was caught, so other read errors skipped the post checkpoint; `bytes` content crashed the emitter | Any exception, and non-text content, becomes a failed read with only the type name |
| 4 | The timeout never fired: the async guard never awaited | Checks run via `asyncio.to_thread`; a test proves the timeout |
| 5 | The post check ignored the name and source actually used, so a rewrite by another control or an approver could swap in a blocked skill | Name and source are re-checked at both points |
| 6 | `Shell-Anything` got only a liftable deny, not `blocked` | Strict name grammar; anything else is a plain `invalid_name` deny |
| 7 | Docs claimed contexts over 5 MiB are denied by default; the SDK enforces no size bound | Claim replaced: the host must bound the read; `max_bytes` capped at 1 MiB |
| 8 | Docs told readers to keep `on_error: deny`, which declaration 1.0 refuses | Sentence removed |
| 9 | The declaration omitted model calls, so a real agent's model calls would all be denied | Surface and passthrough now include the model points |
| 10 | Overstated approval binding: the approver sees name, source and version, not the content | Stated plainly; pin skills once reviewed |
| 11 | Misleading config error message; digest and pattern caveats; sync read blocking the event loop | Reworded, documented, and moved to a thread |
| 12 | Mutations such as `len(content)` for bytes or `>=` for `>` passed all 23 original tests | Parametrized boundary, multibyte and approval cases |

Still open, and documented rather than changed: lifting the guard's deny
skips later controls under the default profile (set
`composition.on_approval` to `resume` if others follow), and the SDK cannot
serialise `bytes` into a context.

## 8. Regression checks

| Check | Result |
| --- | --- |
| Full Python suite before the change | 350 passed, 23 skipped |
| Full Python suite after the fixes | 452 passed, 23 skipped (102 new tests, same skips) |
| Same suite on Python 3.11, 3.12 and 3.14 | 452 passed on each |
| `ruff format --check` and `ruff check` (CI's commands) | pass |
| CI lint scripts: version consistency, spec folders, 85 script tests, file headers | pass |
| Docs site: `mkdocs build --strict` | pass |
| Rust, TypeScript, Go, .NET, spec, schemas, vectors | not touched |

## 9. Cost

Let *n* be the size of the skill text. Gate 1 is a few set lookups
(constant time). Gate 2 encodes the text once, hashes it when a digest is
pinned, folds its case once, and scans it once per forbidden pattern, so
it is linear in *n* for a short pattern list (*O(n·p)* for *p* patterns;
a multi-pattern matcher such as Aho-Corasick brings it to one pass). The
checks run in a worker thread, so the timeout works, but a timed-out check
is abandoned rather than killed, which is why `max_bytes` is capped at
1 MiB. The SDK already pays *O(n)* per checkpoint to fingerprint and copy
the context. Memory is *O(n)* for one skill at a time.

## 10. What the host still has to do

- **One door only.** Every skill must come in through `load_skill`. The
  spec does not promise complete mediation, so a second route would
  bypass the guard.
- **Bound the read.** The SDK does not enforce the recommended 5 MiB
  context bound, so have `read_skill` stop at `max_bytes + 1` bytes.
- **Bind something at the other checkpoints**, including the model ones,
  or enforce mode denies them all.
- **If other controls follow the guard**, set `composition.on_approval`
  to `resume`; otherwise lifting the guard's deny skips them.
- **Load on first use.** Hosts that preload skills still call
  `load_skill` for each one, after startup has been allowed.
- **Treat patterns as a tripwire** and pin digests for skills that matter.

## Running it

```bash
python3 -m venv .venv
.venv/bin/pip install -r sdk/python/requirements-dev.lock
.venv/bin/pip install -e ./sdk/python        # builds the Rust core; needs a Rust toolchain
.venv/bin/pytest sdk/python/tests -p no:agent_hooks_ctk -m "not draft" -q
```

## Attribution and license

This work builds on [responsibleai/agent-hooks](https://github.com/responsibleai/agent-hooks)
by Microsoft, released under the MIT license; see [LICENSE](LICENSE). The
upstream project's README is kept unchanged as
[UPSTREAM-README.md](UPSTREAM-README.md), and the full upstream history is
preserved in this repository. The skill-guard example and its tests are
released under the same license.
