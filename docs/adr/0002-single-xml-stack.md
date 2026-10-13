# One pure-JS XML stack in every environment

The engine bundles a single XML parser and a single canonicalization implementation, and does signature math on WebCrypto, in the browser and in Node alike.
It does not use the browser's `DOMParser` or a native Node XML library, even though both are faster and already present.
We chose this because parser differentials are how signature wrapping bugs happen, and a tool that verifies signatures must never return a different verdict in the CLI than on the web.

## Considered Options

- Native parser per environment.
  Rejected: two parsers mean two verdicts on adversarial input, which is the input that matters.
- libxml2 and xmlsec compiled to WASM.
  Rejected: one code path as well, but a large binary, a harder audit story, and a heavier build for no gain in correctness.

## Consequences

- DTDs and entity declarations are rejected outright rather than handled.
- The adversarial corpus runs in CI in both Node and a real browser, and a differing verdict is a build failure.
- The canonicalizer is the project's own (`packages/core/src/c14n.ts`) and implements exclusive canonicalization only.
  A signature that uses another method is reported as not verified, never as failing or passing.
- The corpus lives in `e2e/corpus.spec.ts`.
  The unit tests sign their fixtures with a separate library, so the canonicalizer is checked against an implementation it does not share code with.
