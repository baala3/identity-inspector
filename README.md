# Identity Inspector

Diagnostics for OIDC, OAuth 2.0, SAML SSO, and SCIM integrations.

It reads what a target publishes, judges it against the specifications, current security practice, and known interop problems, and says plainly which claims were verified and which were only read from a document.

Every finding carries a provenance:

- `discovered` - read from a document the target published
- `user-supplied` - pasted or uploaded by you
- `executed` - a request this tool actually made
- `illustrative` - shown for explanation, never performed

## Use

```sh
pnpm install
pnpm build
node packages/cli/dist/main.js inspect accounts.google.com
node packages/cli/dist/main.js inspect mcp.notion.com
node packages/cli/dist/main.js inspect https://mocksaml.com/api/saml/metadata
node packages/cli/dist/main.js inspect ./idp-metadata.xml --format md
node packages/cli/dist/main.js inspect ./id-token.jwt
node packages/cli/dist/main.js inspect ./saml-response.xml --metadata https://idp.example/metadata
SCIM_TOKEN=... node packages/cli/dist/main.js inspect https://app.example/scim/v2
```

A target with no OpenID configuration that publishes OAuth 2.0 authorization server metadata (RFC 8414) is detected as `oauth`.
It is judged as an authorization server under `oauth.metadata.*` checks, and the rules that only bind an OpenID Provider are not applied.
Most MCP servers are targets of this kind.
Pass `--protocol oauth` to judge a target that publishes both documents by its authorization server metadata.
A file holding an ID token or a JWT access token is checked against the keys of the issuer it names: its signature is verified, and its claims are judged at the evaluation instant.
The report says which of the two kinds it took the token for, and why.
A file holding a SAML response, as XML or as the base64 the browser posted, has its signatures verified and its assertion judged.
With `--metadata` the signatures are checked against the certificates the IdP publishes; without it they can only be shown to be consistent with the certificate carried inside the response, which says nothing about who signed it.
The protocol is detected from the target; pass `--protocol` to skip detection.
The command exits 1 when a finding reaches `--fail-on` (default `error`), so it can gate CI.
`--overview` lists what the target publishes, followed by what no published document can show.
`--at <ISO date>` judges time-bounded evidence as of another instant, for example the moment an incident happened.

## Web interface

```sh
pnpm dev
```

URLs are fetched through a proxy that accepts a URL and nothing else, and refuses anything that is not a public host.
Pasted material is never taken for a URL: under a protocol that cannot read it, it is refused and sent nowhere, here and in the CLI.
Pasted XML is parsed in the browser and is never sent.
A pasted ID token or JWT access token is read and verified in the browser too; only the issuer it names is asked for its public documents.
A pasted SAML response is read and verified in the browser as well, and a second field takes the IdP metadata as a URL or as XML.
Choosing a protocol shapes the form to it: the hint in the target field says what that protocol takes, and SAML offers the IdP metadata field before anything is pasted.
The evaluation instant is offered only where something is judged at one, which is OIDC, SAML, and detection.
Set `IDI_ALLOW_PRIVATE=1` to let the local proxy reach a target on your own machine.

## Status

Milestone 1: static inspection of published documents for all four protocols, in the CLI and the web interface.
Milestone 2, in progress: pasted ID tokens, JWT access tokens, and SAML responses with signature verification are built.
It is hosted at https://identity-inspector.balashekhar.workers.dev.
Encrypted assertions, probes, and live flows are not built yet.

## Layout

- `CONTEXT.md` - the project's vocabulary
- `docs/adr/` - decisions that would otherwise look odd
- `packages/core` - the engine: evidence collection, checks, reports
- `packages/cli` - the `idi` command
- `packages/proxy` - the public-document fetcher, deployed as a Cloudflare Worker that also serves the web interface
- `packages/web` - the web interface

## Develop

```sh
pnpm lint
pnpm typecheck
pnpm test
pnpm e2e:up   # starts Keycloak in Docker
pnpm e2e
```

Check identifiers are a public contract and are never renamed (see `docs/adr/0003-stable-check-ids.md`).
A check needs at least two scenarios with different verdicts in `packages/core/test/checks.test.ts` before it ships.

## Deploy

```sh
pnpm exec wrangler login   # once, from packages/proxy
pnpm deploy
```

One Cloudflare Worker serves the built web interface and answers the proxy under `/api` on the same origin.

## License

Apache-2.0
