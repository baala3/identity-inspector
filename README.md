# Identity Inspector

Diagnostics for OIDC, SAML SSO, and SCIM integrations.

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
node packages/cli/dist/main.js inspect https://mocksaml.com/api/saml/metadata
node packages/cli/dist/main.js inspect ./idp-metadata.xml --format md
node packages/cli/dist/main.js inspect ./id-token.jwt
SCIM_TOKEN=... node packages/cli/dist/main.js inspect https://app.example/scim/v2
```

A file holding an ID token is checked against the keys of the issuer it names: its signature is verified, and its claims are judged at the evaluation instant.
The protocol is detected from the target; pass `--protocol` to skip detection.
The command exits 1 when a finding reaches `--fail-on` (default `error`), so it can gate CI.
`--at <ISO date>` judges time-bounded evidence as of another instant, for example the moment an incident happened.

## Web interface

```sh
pnpm dev
```

URLs are fetched through a proxy that accepts a URL and nothing else, and refuses anything that is not a public host.
Pasted XML is parsed in the browser and is never sent.
A pasted ID token is read and verified in the browser too; only the issuer it names is asked for its public documents.
Set `IDI_ALLOW_PRIVATE=1` to let the local proxy reach a target on your own machine.

## Status

Milestone 1: static inspection of published documents for all three protocols, in the CLI and the web interface.
Milestone 2, in progress: pasted ID tokens with signature verification are built.
It is hosted at https://identity-inspector.balashekhar.workers.dev.
Pasted SAML assertions, probes, and live flows are not built yet.

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
