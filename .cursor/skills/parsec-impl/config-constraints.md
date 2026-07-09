# Fail-Safe Configuration Constraints

All config changes in parsec MUST be **backward compatible**.

## Hard Rule

Code deploys before config. If a new config field is missing (because
app-interface hasn't been updated yet), the system MUST behave identically
to the previous version. New behavior activates only when the config is
explicitly provided. No panics, no errors, no degraded behavior from
absent config.

## How to Achieve This

- New fields must have **sensible zero-value or explicit defaults** that
  preserve prior behavior
- Use `With…` option functions or pointer/optional types where appropriate
  so that "not set" is distinguishable from "set to zero"
- Never `panic` or `log.Fatal` on missing new config — fall back gracefully
- Feature-gate new behavior behind the new config: old config = old behavior
- Include a **test that verifies behavior with the field absent/zero-valued**
  matches the previous behavior

## In the Plan Template

When filling out the Configuration Impact section of a plan, use the
Backward Compatibility table to document each new field's type, default,
and what happens when it is absent. Refer to
`.cursor/rules/deploy-config-sync.mdc` for downstream app-interface paths
and validation checks.
