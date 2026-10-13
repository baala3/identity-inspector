# Identity Inspector

Diagnostics for OIDC, OAuth 2.0, SAML SSO, and SCIM integrations.

It reads what a target publishes and judges it against the specifications, current security practice, and known interop problems.
It says plainly which claims were verified and which were only read from a document.

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

The protocol is detected from the target.
What it takes beyond an OIDC issuer, SAML metadata, or a SCIM base URL:

- **OAuth authorization server** - a target with no OpenID configuration that publishes RFC 8414 metadata is detected as `oauth`.
  It is judged under `oauth.metadata.*` checks, without the rules that only bind an OpenID Provider.
  Most MCP servers are this kind.
- **ID token or JWT access token** - the signature is verified against the keys of the issuer it names, and the claims are judged at the evaluation instant.
  The report says which kind it took the token for, and why.
- **SAML response**, as XML or as the base64 the browser posted - its signatures are verified and its assertion judged.

| Flag | Effect |
| --- | --- |
| `--protocol` | Skips detection. `oauth` judges a target that publishes both documents by its authorization server metadata. |
| `--metadata` | Checks SAML signatures against the certificates the IdP publishes. Without it they are only shown consistent with the certificate inside the response, which says nothing about who signed it. |
| `--fail-on` | Exits 1 when a finding reaches this severity (default `error`), so it can gate CI. |
| `--overview` | Lists what the target publishes, then what no published document can show. |
| `--at <ISO date>` | Judges time-bounded evidence as of another instant, such as the moment of an incident. |

## Web interface

```sh
pnpm dev
```

- **URLs** go through a proxy that accepts a URL and nothing else, and refuses any host that is not public.
  Set `IDI_ALLOW_PRIVATE=1` to let the local proxy reach a target on your own machine.
- **Pasted material** is never taken for a URL.
  Under a protocol that cannot read it, it is refused and sent nowhere, here and in the CLI.
- **Pasted XML, tokens, and SAML responses** are read and verified in the browser.
  Pasted XML is never sent, and for a token only the issuer it names is asked for its public documents.
  A second field takes the IdP metadata for a SAML response, as a URL or as XML.
- **The form follows the protocol chosen**: the target hint says what that protocol takes, and SAML offers the IdP metadata field up front.
  The evaluation instant appears only for OIDC, SAML, and detection, where something is judged at one.

## Status

Hosted at https://identity-inspector.balashekhar.workers.dev.

- **Milestone 1, done**: static inspection of published documents for all four protocols, in the CLI and the web interface.
- **Milestone 2, in progress**: pasted ID tokens, JWT access tokens, and SAML responses with signature verification are built.
- **Not built yet**: encrypted assertions, probes, and live flows.

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
