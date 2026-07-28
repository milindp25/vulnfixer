# nexus-autofix — Implementation Spec

Status: approved for implementation
Source design: user-supplied `nexus-autofix-design.md` (Rev 3), `agent-instructions.md`,
`prompt-template.md`, and playbooks `npm.md`, `spring-boot-gradle.md`, `spring-boot-maven.md`
(all copied verbatim into the package — see below).

This spec records the scoping decisions made on top of the source design doc; it does not
restate that doc's content, which remains the authority for architecture, data models, IQ
endpoint sequence, playbook mechanisms, and prohibitions.

## Scope

Build the full v0 system in one pass:

- Domain model (`Finding`, `RepoProfile`, `RunOutcome`, etc.)
- Two-tier repo/toolchain detection (`.trident/build.yaml` primary, glob fallback)
- Nexus IQ client: real HTTP implementation (`IQClient` Protocol) + `FakeIQClient` test double
- Agent layer: `AgentRunner` Protocol + `MockAgent` test double + `copilot_cli.py` real adapter
- Verification: toolchain resolution, build/test command wrapper, diff classifier, rescan comparison
- Orchestrator loop (the full run flow in source doc section 8) + SQLite state store
- Publish: branch lifecycle, PR creation, human-in-loop gate presentation
- CLI (`nexusfix run`, `nexusfix gc`)
- Playbooks and agent-instructions files copied in verbatim, `agent/prompt.py` assembling them
  per `prompt-template.md`

Out of scope (per source doc): the MCP server wrapper (explicitly deferred), enterprise CI
trigger / GitHub Actions integration, anything requiring a live IQ tenant to confirm (exact
`.trident` key nesting, real endpoint field names) — these are implemented per the doc's stated
assumptions with tolerant parsing, not guessed beyond what the doc specifies.

## Decisions made in scoping (this session)

1. **Platform**: cross-platform. `verify/toolchain.py` and `verify/commands.py` resolve
   `./gradlew` vs `gradlew.bat`, `./mvnw` vs `mvnw.cmd`, and toolchain paths via `pathlib`,
   not hardcoded Windows drive letters. `config.yml`'s toolchain map accepts plain path strings
   for either OS.
2. **Real integrations are written to spec, not stubbed, but unverified.** `iq/client.py`'s HTTP
   implementation follows the exact endpoint sequence in source doc section 7. `agent/copilot_cli.py`
   invokes the Copilot CLI per section 16's description. Neither has been exercised against a live
   Nexus IQ instance or an installed Copilot CLI in this environment — the user will test both on
   their corporate machine and report back issues (wrong endpoint shape, auth handling, CLI flags
   that don't match) for follow-up fixes. This is stated in code comments at both integration
   points and in the final implementation report, not left implicit.
3. **A working offline fixture demo is required, not just unit tests.** `tests/fixtures/demo_gradle_repo/`
   is a small real Gradle project (its own git history) with one genuinely outdated dependency.
   `tests/test_orchestrator_e2e.py` runs `orchestrator.run()` against it with `FakeIQClient`
   returning a canned finding and `MockAgent` in `APPLIES_FIX` mode — real git, real `./gradlew`,
   nothing mocked except the two external services. A second e2e case runs `MockAgent(mode=DELETES_TEST)`
   and asserts the orchestrator aborts as `ESCALATED` without ever pushing — this is the specific
   behavior source doc section 12 calls out as otherwise untestable.

## Layout

```
nexus_autofix/
├─ pyproject.toml            # console script `nexusfix`; deps: requests, pyyaml, python-dotenv, click
├─ cli.py
├─ config.py
├─ orchestrator.py
├─ iq/  client.py  models.py  remediation.py  filter.py
├─ repo/  workspace.py  trident.py  detect.py  descriptor.py
├─ agent/  base.py  mock.py  copilot_cli.py  prompt.py
├─ verify/  toolchain.py  commands.py  rescan.py  diff.py
├─ publish/  branch.py  pr.py  gate.py
├─ playbooks/  spring-boot-gradle.md  spring-boot-maven.md  npm.md
├─ agent_instructions.md
state/store.py
tests/
├─ unit/                          # one file per module above
├─ fixtures/demo_gradle_repo/
└─ test_orchestrator_e2e.py
```

`state/`, `runs/`, `.env` gitignored. `config.yml` checked in with placeholder toolchain paths
and an empty `repos:` map.

## Testing strategy

Unit tests per module: trident parser (both key-nesting cases per source doc's stated
tolerance requirement), filter logic's include/escalate/ignore matrix, diff classifier against
one synthetic diff per SUSPICIOUS trigger listed in source doc section 11, versionChanges type
selection ladder, toolchain major-version matching. Fixture e2e tests as described above are the
primary proof the orchestrator works end-to-end.

## Non-goals carried over from source doc (do not implement)

Everything in the source doc's "Absolute prohibitions" and "Prohibited" sections across
`agent-instructions.md` and the playbooks applies to what the **target-repo agent** is allowed
to do — these are prompt content, not nexus-autofix behavior to build, but the orchestrator's
own diff classifier must actively detect and abort on them (this is in scope, covered above).
