# The proxy sends named probes, never arbitrary requests

Active checks need non-GET requests, for example sending a wrong PKCE verifier to a token endpoint.
The proxy exposes a fixed catalog of named probes whose method, headers, and body it builds itself.
The caller chooses only which probe to run and against which target, and the target endpoint must come from a document the proxy fetched itself, not from the caller.
We chose this over request passthrough because an anonymous public service that will send any request to any host is an attack relay.

## Considered Options

- GET-only proxy, with probes available only in the CLI.
  Rejected: nothing on the web could earn the executed provenance, which is the main thing the tool offers over reading a discovery document.
- Arbitrary request passthrough with rate limits.
  Rejected: rate limits bound the volume of abuse, not the kind.

## Consequences

- Adding a probe is a proxy deployment, not a client change.
- Outbound requests are restricted to public addresses, re-checked after DNS resolution and after every redirect.
