---
name: parsec-impl
description: >-
  Plan and implement new features or large changes in parsec. Gathers JIRA
  context, acceptance criteria, and external references (Google Docs, other
  repos), then produces a comprehensive implementation plan aligned with parsec
  conventions. Use when starting a new feature, large refactor, or significant
  change in parsec.
disable-model-invocation: true
---

# parsec-impl — Feature Implementation Planner

## Overview

This skill walks through gathering requirements, verifying access to external
tools, analyzing the task against parsec architecture, and producing a
reviewable implementation plan. The plan is iterative — users review, comment,
and refine before execution begins.

**Compatibility**: Works in both Cursor and Claude CLI. For Claude CLI, symlink
or copy this skill folder into `.claude/skills/parsec-impl/`. When
`AskQuestion` is unavailable, ask the same questions conversationally. When
`SwitchMode` is unavailable, proceed without mode switching. See
[README.md](README.md) for setup instructions.

## Phase 1: Gather Inputs

Collect the following from the user. Use `AskQuestion` for structured choices
where applicable.

### 1.1 JIRA Reference

Ask for the JIRA issue key (e.g. `KESSEL-123`, `RHCLOUD-456`).

**Verify JIRA MCP access:**

1. Call `getAccessibleAtlassianResources` via the `user-Atlassian-MCP-Server` MCP.
2. If it succeeds, use `getJiraIssue` with the provided key to fetch:
   - Summary, description, acceptance criteria, status, priority, labels, components
   - Use `fields: ["*all"]` and `responseContentFormat: "markdown"`
3. If the MCP call fails with an auth error, guide the user:

> **JIRA MCP not configured.** To enable automatic JIRA access:
>
> 1. Install the [Atlassian MCP Server](https://www.npmjs.com/package/@anthropic/atlassian-mcp-server) or configure it via Cursor Settings > MCP.
> 2. Authenticate with your Atlassian account when prompted.
> 3. Retry this skill after setup.
>
> **Or paste the JIRA issue content directly** — copy the description and acceptance criteria from your browser.

If the user pastes content, proceed with that.

### 1.2 Acceptance Criteria

Extract acceptance criteria from the JIRA issue if available. If the JIRA issue
lacks clear acceptance criteria, ask the user to provide or confirm them.

Present the extracted/provided criteria back to the user for confirmation before
proceeding.

### 1.3 External References

Ask: _"Are there any external references for this work?"_

Use `AskQuestion` with options:
- Google Doc / Google Drive link
- Link to another repository
- Confluence page
- Other URL / document
- No additional references

**For Google Docs/Drive content**, offer these access methods (in order of preference):

1. **GWS CLI/SDK** — If `gws` is available on the machine, fetch the document:
   ```bash
   # Check if gws is installed
   which gws
   # Fetch document content (extract doc ID from URL)
   gws docs get <doc-id> --format=text
   ```
   Extract the document ID from the Google Docs URL (the long alphanumeric string
   between `/d/` and `/edit`).

2. **Google Drive MCP** — If a Google Drive/Docs MCP server is configured, use
   it to fetch the document. Check available MCP servers by listing the
   `mcps/` directory in the project config.

3. **Manual paste** — Ask the user to copy-paste the relevant content:

> **No automated Google Docs access found.**
>
> Options to set up access:
> - **GWS CLI**: Install via `pip install gws-cli` or see your org's GWS SDK docs. Then run `gws auth login`.
> - **Google Drive MCP**: Add a Google Drive MCP server in Cursor Settings > MCP (e.g. [@anthropic/google-drive-mcp](https://www.npmjs.com/package/@anthropic/google-drive-mcp)).
>
> **Or paste the document content here** and we'll proceed.

**For Confluence pages**, use the `getConfluencePage` or `searchConfluenceUsingCql`
tools via the Atlassian MCP (same server as JIRA).

**For other URLs**, use `WebFetch` to retrieve content.

## Phase 2: Analyze the Task

Before planning, build context from the parsec codebase:

### 2.1 Discover & Read Architecture and Design Docs

Do NOT use a hardcoded list of docs — the team continuously adds and updates
architecture and design documents. Discover them dynamically:

1. Read `AGENTS.md` at the repo root (always present, contains pointers to conventions).
2. Glob for `docs/**/*.md` to find all documentation files.
3. Exclude files that are clearly review artifacts (e.g. `pr-*-review.md`,
   `benchmark-results-*.md`) — these are PR-specific, not architectural.
4. Read every remaining doc. These are the architecture, design, and convention
   references that the plan must align with.

This ensures the plan always reflects the latest conventions, even as new docs
are added (e.g. a future `docs/caching-design.md` or `docs/error-handling.md`
will be picked up automatically).

### 2.2 Explore Affected Code

Based on the JIRA description and acceptance criteria:
1. Identify which packages are affected (use `SemanticSearch` and `Grep`)
2. Read the key files that will be modified
3. Understand the existing interfaces and types involved
4. Identify the observer hierarchy if observability is involved
5. Look at existing tests in affected packages for patterns

### 2.3 Identify Configuration Impact

Determine whether the change touches configuration at any layer:

1. **Local config** — Check `internal/config/` for affected fields, loaders,
   and flags. Inspect `configs/` for example/default config files. Read the
   existing config struct (`internal/config/config.go`) and any related files
   (`internal/config/issuers.go`, `internal/config/datasources.go`, etc.)
2. **Deploy templates** — Check `deploy/` for deployment manifests, Dockerfiles,
   or environment variable references that may need updating.
3. **Downstream app-interface** — Per `.cursor/rules/deploy-config-sync.mdc`,
   if any config field is added, removed, or renamed, the downstream
   **app-interface** secrets must also be updated. Refer to the rule for
   specific paths and validation checks.

**Fail-safe constraint**: Every config change MUST be backward compatible.
If the new config field is absent (because downstream app-interface hasn't been
updated yet), the code must behave exactly as it did before the change — no
panics, no broken behavior, no degraded functionality. The new behavior only
activates once the config is explicitly provided. This ensures safe rollouts
where code deploys before config updates.

Flag any config impact found — it will feed into the plan's Configuration
Impact section.

### 2.4 Identify Other Constraints

Document any additional constraints discovered:
- Existing interface contracts that must be preserved
- gRPC/protobuf API compatibility
- Package dependency direction

## Phase 3: Build the Implementation Plan

Produce the plan using the template in [plan-template.md](plan-template.md).
Save the plan to `docs/impl-plans/<JIRA-KEY>.md`.

The plan must address **all** of the following:

### 3.1 Design Decisions
- Architectural approach with rationale
- Trade-offs considered and why the chosen approach wins
- Interface changes (if any) and backward compatibility

### 3.2 Implementation Steps & PR Boundaries
- Ordered list of changes grouped by package/concern
- Each step should be small enough to be a reviewable unit
- Identify which steps can be parallelized vs. must be sequential
- **PR splitting**: When the overall change is large, group steps into
  distinct PRs that can be reviewed and merged independently. Each PR
  should be self-contained — it compiles, tests pass, and doesn't break
  existing behavior. Mark PR boundaries clearly in the plan:
  - `PR 1: <title>` — steps 1–3 (e.g. interfaces and NoOps)
  - `PR 2: <title>` — steps 4–5 (e.g. implementation)
  - `PR 3: <title>` — steps 6–7 (e.g. observability and wiring)
- Some work genuinely can't be split (e.g. a tightly coupled interface
  change and its only implementation). Note these as "atomic" and explain
  why. Everything else should be split to keep PRs reviewable.

### 3.3 Naming Conventions
- Proposed type, function, and variable names
- Must follow parsec conventions: descriptive, domain-oriented names
- Observer/Probe names per `docs/observer-pattern.md`

### 3.4 Test Coverage
- Per `docs/testing.md`: hermetic, no I/O, no mocks, prefer fakes
- List specific test cases for each component
- Contract tests for new interfaces
- Benchmark tests if performance-sensitive paths are touched
- Deterministic concurrency tests if goroutines are involved

### 3.5 Observability
- Per `docs/observer-pattern.md`: Observer/Probe interfaces, NoOp implementations
- Observer hierarchy placement (leaf, intermediate, aggregate)
- Injection convention (constructors accept leaf observer)
- OTel metrics: `WithAttributeSet`, pre-built attribute sets, histogram conventions

### 3.6 Security
- Credential handling per `docs/CREDENTIAL_DESIGN.md`
- Input validation and sanitization
- Error messages that don't leak internals
- TLS/mTLS considerations if applicable

### 3.7 Maintainability
- Constructor pattern: required params positional, optional via `With…` options
- Forward compatibility: NoOp embedding for interfaces
- Config layer concerns vs. domain concerns separation
- Package boundaries and dependency direction

### 3.8 Configuration Impact

All config changes MUST be **fail-safe and backward compatible**:

> **Hard rule**: Code deploys before config. If a new config field is missing
> (because app-interface hasn't been updated yet), the system MUST behave
> identically to the previous version. New behavior activates only when the
> config is explicitly provided. No panics, no errors, no degraded behavior
> from absent config.

How to achieve this:
- New fields must have **sensible zero-value or explicit defaults** that
  preserve prior behavior
- Use `With…` option functions or pointer/optional types where appropriate
  so that "not set" is distinguishable from "set to zero"
- Never `panic` or `log.Fatal` on missing new config — fall back gracefully
- Feature-gate new behavior behind the new config: old config = old behavior
- Include a **test that verifies behavior with the field absent/zero-valued**
  matches the previous behavior

If the change touches configuration at **any** layer, the plan must include
explicit steps for each:

**Local config (parsec repo):**
- New/changed fields in `internal/config/` structs with safe defaults
- Updated loaders, flags, or defaults in `internal/config/flags.go`
- Example config files in `configs/` updated to reflect new fields
- Validation logic for new fields (must accept absent/zero gracefully)

**Deploy templates (parsec repo):**
- Changes to `deploy/` manifests, env vars, volume mounts, etc.

**Downstream app-interface (separate repo — MUST be called out as a follow-up):**

> **IMPORTANT**: Remind the user that downstream deployment config must be
> updated separately in the **app-interface** repo. This is easy to forget
> and will cause stage/prod drift.

Include a dedicated step in the plan referencing
`.cursor/rules/deploy-config-sync.mdc` for the specific paths and checks
that must be applied to stage and prod environments.

If the change has **no** config impact, state that explicitly so reviewers
know it was considered and not overlooked.

### 3.9 Documentation
- **New docs**: If the change introduces a new architectural pattern, design
  decision, or convention, include a step to create or update a doc in `docs/`.
  The doc should follow the style of existing docs (concise, pattern-oriented,
  with Go code examples).
- **Existing docs**: If the change modifies behavior covered by an existing doc,
  include a step to update that doc to stay accurate.
- **AGENTS.md**: If the change introduces a new convention (e.g. a new testing
  pattern, a new constructor idiom), include a step to update `AGENTS.md` with
  a pointer to the relevant doc.
- **Code comments**: Inline comments only for non-obvious intent, trade-offs,
  or constraints. No narration of what the code does.
- **Config examples**: If new configuration fields are added, include example
  YAML snippets in the relevant doc or in the plan itself.

### 3.9 Completeness Checklist

Before presenting the plan, verify everything is in order:

- [ ] Every acceptance criterion has at least one implementation step addressing it
- [ ] Every new exported type/function has a proposed name following parsec conventions
- [ ] Every new interface has a NoOp implementation planned
- [ ] Every new component that needs observability has observer/probe entries
- [ ] Test cases exist for all new behavior (unit, contract, benchmark as appropriate)
- [ ] Security implications are addressed (or explicitly noted as N/A)
- [ ] Documentation steps are included for any new or changed patterns
- [ ] Config impact assessed: local config, deploy templates, and downstream app-interface
- [ ] All new config fields are fail-safe: absent/zero-value preserves previous behavior
- [ ] Test exists verifying behavior with new config field absent (backward compat)
- [ ] If config changes exist, explicit follow-up step for app-interface stage + prod updates
- [ ] No step is too large — each should be a reviewable, self-contained unit
- [ ] Large changes are split into distinct PRs with clear boundaries
- [ ] Each PR compiles, tests pass, and doesn't break existing behavior independently
- [ ] The plan can be executed top-to-bottom without ambiguity

### 3.10 Risks & Open Questions
- Anything that needs clarification before implementation
- Known risks and mitigation strategies

## Phase 4: Plan Review & Iteration

After presenting the plan, offer the user these actions via `AskQuestion`:

| Action | Behavior |
|--------|----------|
| **Iterate on the plan** | User provides comments/feedback; update specific sections while preserving the rest. Re-present the updated plan. |
| **Update a section** | User specifies which section to revise; make targeted changes. |
| **Scrap and start new** | Delete the current plan file and restart from Phase 1. |
| **Delete the plan** | Delete the plan file and end. |
| **Execute the plan** | Transition to implementation mode — begin executing the plan step by step. |

### Handling Comments During Iteration

When the user provides feedback:
1. Acknowledge each comment specifically
2. Explain what will change and why
3. Update the plan file in place
4. Re-present only the changed sections (not the full plan)
5. Offer the action menu again

### Executing the Plan

When the user chooses "Execute the plan":

1. Switch to Agent mode if not already in it
2. If the plan has multiple PRs defined, ask which PR to execute (or start
   from PR 1)
3. Create a todo list from the steps in the current PR scope
4. Work through each step, following parsec conventions
5. After each significant step, run tests (`go test ./...`)
6. Check lints after edits
7. Update the plan file to mark completed steps
8. When all steps for the current PR are done:
   - Run full test suite (`go test ./...`)
   - Confirm all tests pass and lints are clean
   - Offer to create the PR (commit, push, `gh pr create`)
   - Then ask: continue to the next PR, or stop here?
9. Repeat for each subsequent PR until the plan is fully executed

## Reference Docs

- For plan output format, see [plan-template.md](plan-template.md)
- For MCP and tool setup instructions, see [mcp-setup-guide.md](mcp-setup-guide.md)
