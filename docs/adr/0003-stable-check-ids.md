# Check identifiers are a public contract

Every check has a dotted identifier such as `saml.sig.sha1` or `oidc.jwks.kid-missing`, and once released an identifier is never renamed or reused for a different rule.
A check that is retired keeps its identifier reserved, and a rule whose meaning changes gets a new identifier.
We chose this because identifiers appear in exported reports, in CI suppression lists, and in documentation URLs, so renaming one silently un-suppresses or mis-suppresses findings in other people's pipelines.

## Consequences

- No check ships without a fixture that triggers it and a fixture that passes it, keyed by its identifier.
- Tidying up the naming scheme later is not available as a refactor.

## Exceptions

- Six checks released as `oidc.id-token.*` (`format`, `alg`, `key`, `signature`, `issuer`, `time`) were renamed to `oidc.token.*` within hours of their release, at version 0.0.0, when access tokens turned out to need the same checks.
  The old identifiers stay reserved and are not reused.
  This was possible only because nothing could yet depend on them, and it is not a precedent for renaming an identifier that has been in use.
