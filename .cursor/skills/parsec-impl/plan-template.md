# Plan Template

Use this template when generating implementation plans. Save output to
`docs/impl-plans/<JIRA-KEY>.md`.

---

```markdown
# <JIRA-KEY>: <Summary>

**JIRA**: <link>
**Status**: Draft | In Review | Approved | In Progress | Done
**Author**: <name>
**Date**: <date>

## Context

<Brief description of the problem/feature from JIRA. Include acceptance criteria.>

### Acceptance Criteria

- [ ] AC1: ...
- [ ] AC2: ...

### External References

- <links to Google Docs, Confluence, other repos, etc.>

## Design

### Approach

<Describe the chosen architectural approach and rationale.>

### Alternatives Considered

| Alternative | Pros | Cons | Why not |
|-------------|------|------|---------|
| ... | ... | ... | ... |

### Interface Changes

<New or modified interfaces. Show Go code snippets. Note backward compatibility.>

### Package Impact

| Package | Change Type | Description |
|---------|------------|-------------|
| `internal/...` | New / Modified | ... |

## Implementation Steps

Steps are ordered. Each should be a reviewable unit of work.
When the change is large, steps are grouped into distinct PRs. Each PR
must be self-contained: compiles, tests pass, no behavior regressions.

### PR 1: <Title> (e.g. "Interfaces and NoOps")

#### Step 1: <Title>

**Package**: `internal/...`
**Files**: `file1.go`, `file2.go`
**Status**: Pending | In Progress | Done

<Description of changes.>

**Key types/functions**:
- `TypeName` — purpose
- `FunctionName` — purpose

#### Step 2: <Title>

...

---

### PR 2: <Title> (e.g. "Core implementation")

#### Step 3: <Title>

...

---

_If the change is small enough for a single PR, use just one PR section.
Mark steps as "atomic" if they cannot be split across PRs, with a brief
explanation why._

## Naming

| Entity | Name | Rationale |
|--------|------|-----------|
| Type | `FooBar` | ... |
| Function | `NewFooBar` | ... |
| Observer | `FooBarObserver` | Per observer-pattern.md |
| Probe | `FooBarProbe` | Per observer-pattern.md |

## Test Plan

Per `docs/testing.md`: hermetic, no I/O, no mocks, prefer real instances and fakes.

### Unit Tests

| Test | Package | What it verifies |
|------|---------|-----------------|
| `TestFoo_DoesBar` | `internal/...` | ... |

### Contract Tests

<For new interfaces: shared test suite that all implementations must pass.>

### Benchmarks

<If performance-sensitive paths are affected.>

| Benchmark | Package | What it measures |
|-----------|---------|-----------------|
| `BenchmarkFoo` | `internal/...` | ... |

### Integration / E2E

<If new end-to-end flows are introduced.>

## Observability

Per `docs/observer-pattern.md`.

### Observer Hierarchy

```
<PackageName>Observer              (package aggregate)
├── <Interface>Observer            (intermediate — if needed)
│   └── <Implementation>Observer   (leaf)
```

### New Probes

| Probe | Metrics | Logs | Key Attributes |
|-------|---------|------|----------------|
| `FooProbe` | `foo_duration_seconds` (histogram) | Info/Error at End() | status, result |

### Injection

<Which constructors accept which observer level.>

## Security

- [ ] Input validation: ...
- [ ] Error handling: no internal leaks in error messages
- [ ] Credential handling per `docs/CREDENTIAL_DESIGN.md`: ...
- [ ] TLS/mTLS considerations: ...

## Maintainability

- [ ] Constructor pattern: required params positional, optional via `With…`
- [ ] Forward compatibility: NoOp embedding on all new interfaces
- [ ] Config vs. domain separation: ...
- [ ] Downstream app-interface impact: ...

## Configuration Impact

> **Fail-safe rule**: All config changes must be backward compatible. If a new
> field is absent (app-interface not yet updated), the system behaves exactly as
> before. New behavior activates only when config is explicitly provided.

### Backward Compatibility

| New Field | Type | Default / Zero Value | Behavior When Absent |
|-----------|------|---------------------|----------------------|
| `...` | `string` / `*Type` / ... | `""` / `nil` / ... | Preserves previous behavior: ... |

- [ ] Every new field has a safe default that preserves prior behavior
- [ ] No `panic` or `log.Fatal` on missing new config
- [ ] Test verifies behavior with new field absent matches previous version

### Local Config (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `internal/config/config.go` | New field / Modified | ... (default: ...) |
| `internal/config/flags.go` | New flag / Modified | ... |
| `configs/...` | Updated example | ... |

### Deploy Templates (parsec repo)

| File | Change | Description |
|------|--------|-------------|
| `deploy/...` | ... | ... |

### Downstream app-interface (follow-up required)

> **Action required after merge**: Update the downstream app-interface secrets
> to reflect config changes. Until updated, the new code runs with previous
> behavior (fail-safe). Once config is applied, new behavior activates.
>
> Refer to `.cursor/rules/deploy-config-sync.mdc` for specific paths and
> validation checks for stage and prod environments.

| Environment | What to update |
|-------------|----------------|
| Stage | ... |
| Prod | ... |

_If no config impact: state "No configuration impact — reviewed and confirmed."_

## Documentation

### New Documentation

| Doc | Path | Purpose |
|-----|------|---------|
| ... | `docs/...` | ... |

### Documentation Updates

| Doc | Path | What changes |
|-----|------|-------------|
| ... | `docs/...` | ... |
| ... | `AGENTS.md` | ... (if new conventions introduced) |

### Config Examples

<Example YAML snippets for any new configuration fields.>

## Completeness Checklist

- [ ] Every acceptance criterion maps to at least one implementation step
- [ ] Every new exported type/function has a proposed name
- [ ] Every new interface has a NoOp implementation planned
- [ ] Every observable component has observer/probe entries
- [ ] Test cases cover all new behavior
- [ ] Security implications addressed (or marked N/A)
- [ ] Documentation steps included for new/changed patterns
- [ ] Config impact assessed: local config, deploy templates, and downstream app-interface
- [ ] All new config fields are fail-safe: absent/zero-value preserves previous behavior
- [ ] Test exists verifying behavior with new config field absent (backward compat)
- [ ] If config changes exist, explicit follow-up step for app-interface stage + prod updates
- [ ] Each step is a reviewable, self-contained unit
- [ ] Large changes are split into distinct PRs with clear boundaries
- [ ] Each PR compiles, tests pass, and doesn't break existing behavior independently
- [ ] Plan can be executed top-to-bottom without ambiguity

## Risks & Open Questions

| # | Item | Status | Resolution |
|---|------|--------|------------|
| 1 | ... | Open / Resolved | ... |

## Review Log

| Date | Reviewer | Feedback | Changes Made |
|------|----------|----------|--------------|
| ... | ... | ... | ... |
```
