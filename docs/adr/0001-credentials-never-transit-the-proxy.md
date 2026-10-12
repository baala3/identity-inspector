# Credentials never transit the proxy

The hosted proxy only fetches public documents and sends named probes.
Anything involving a credential (a SCIM bearer token, a client secret, an authorization code and its verifier, an SP private key) is handled either in the user's browser or in the CLI on the user's machine.
We chose this because a public tool that asks for production assertions and tokens is only credible if the operator provably cannot see them, and "we do not log it" is not provable.

## Considered Options

- Relay authenticated requests through the proxy without logging.
  Rejected: it makes most SCIM checks work on the web, but the trust claim becomes a promise instead of a property of the design.
- Browser-only, no proxy at all.
  Rejected: CORS blocks most discovery, metadata, and SCIM fetches, so the web interface would be nearly useless.

## Consequences

- Authenticated SCIM checks are CLI-only, since SCIM servers rarely send CORS headers.
  The web interface says so and hands the user the exact CLI command.
- The live OIDC flow on the web exchanges the code browser-direct.
  When the token endpoint does not allow that, it is reported as a finding and the user is pointed at the CLI loopback flow.
- A hosted mock SCIM server is out of scope until this decision is revisited, because it would have to store directory data.
