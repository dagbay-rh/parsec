# Completeness Checklist

Verify all items before presenting or approving the plan.

- [ ] **Server code vs. configuration gate passed**: no deployment-specific,
      IdP-specific, or vendor-specific logic in server Go code. If server code
      is modified, the change is generic — valid for any IdP, vendor, and
      deployment.
- [ ] If a new abstraction/policy layer is needed, it is a separate PR from
      the use case that consumes it.
- [ ] Every acceptance criterion maps to at least one implementation step
- [ ] Every new exported type/function has a proposed name following parsec conventions
- [ ] Every new interface has a NoOp implementation planned
- [ ] Every observable component has observer/probe entries
- [ ] Test cases cover all new behavior (unit, contract, benchmark as appropriate)
- [ ] Security implications addressed (or marked N/A)
- [ ] Documentation steps included for new/changed patterns
- [ ] Config impact assessed: local config, deploy templates, and downstream app-interface
- [ ] All new config fields are fail-safe (see [config-constraints.md](config-constraints.md))
- [ ] Test exists verifying behavior with new config field absent (backward compat)
- [ ] If config changes exist, explicit follow-up step for app-interface stage + prod updates
- [ ] Each step is a reviewable, self-contained unit
- [ ] Large changes are split into distinct PRs with clear boundaries
- [ ] Each PR compiles, tests pass, and doesn't break existing behavior independently
- [ ] Plan can be executed top-to-bottom without ambiguity
