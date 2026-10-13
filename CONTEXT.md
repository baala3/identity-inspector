# Identity Inspector

A diagnostics tool for OIDC, OAuth 2.0, SAML SSO, and SCIM integrations.
It exists to tell an engineer what is actually wrong with an integration, and to be explicit about which claims were verified and which were only read from a document.

## Language

### Subjects

**Protocol**:
One of OIDC, OAuth, SAML, or SCIM.
A target that publishes an OpenID configuration is OIDC; OAuth is a server that publishes only authorization server metadata, or one the user asks to have judged that way.
_Avoid_: Standard, integration type

**Role**:
The part a party plays in a protocol: OpenID Provider, Relying Party, Authorization Server, Client, SAML Identity Provider, SAML Service Provider, SCIM Server, or SCIM Client.
The SCIM Server is hosted by the application and the SCIM Client is the directory that provisions into it.
_Avoid_: Side, direction, IdP as a catch-all for every server-side role

**Target**:
The party under inspection, identified by a protocol and a role.
_Avoid_: Provider, tenant, subject

**Profile**:
A named body of knowledge about one vendor's behaviour in a role, verified against a live tenant of that vendor.
_Avoid_: Quirk list, vendor plugin, preset

### Inputs

**Evidence**:
A single artifact about a target: a discovery document, authorization server metadata, a key set, a metadata document, a token, an assertion, a request, or a response.
_Avoid_: Input, payload, sample

**Workspace**:
The set of evidence gathered about one target, evaluated together so that one artifact can be checked against another.
_Avoid_: Session, project, case

**Evaluation instant**:
The moment in time at which time-bounded evidence is judged, defaulting to now.
_Avoid_: Clock, timestamp, as-of date

**Probe**:
A request with a fixed, named shape that the tool itself sends to a target to observe behaviour.
_Avoid_: Test request, ping, scan

**Live flow**:
A complete protocol exchange in which the tool acts as a real counterparty to the target.
_Avoid_: End-to-end test, real login

### Outputs

**Check**:
A single named rule that examines a workspace and produces findings.
Each check has a stable identifier that is a public contract.
_Avoid_: Rule, test, validator, lint

**Finding**:
The result of one check against one workspace: a verdict about a specific piece of evidence.
A finding exists for a passing check as well as a failing one.
_Avoid_: Issue, error, result, diagnostic

**Category**:
The standard a finding is judged against: conformance (the specification), security (best current practice), or interop (specification-legal but breaks with a known counterparty).
_Avoid_: Type, kind, tag

**Severity**:
How much a finding matters: error, warn, info, or pass.
_Avoid_: Level, priority

**Provenance**:
How the fact behind a finding or a flow step was obtained: discovered (read from a document the target published), illustrative (shown for explanation, never performed), executed (a request the tool actually made), or user-supplied (pasted or uploaded by the user).
_Avoid_: Source, origin, confidence

**Citation**:
The specification section or published guidance that a finding rests on.
_Avoid_: Reference, link, source

**Remediation**:
What to change to resolve a finding, stated separately for each role that could act on it.
_Avoid_: Fix, suggestion, advice

**Overview**:
What the evidence states about a target, restated with no verdict attached.
_Avoid_: Summary, configuration, details

**Unseen**:
What evidence of the kind gathered can never show, however it is read, listed so that silence is not taken for a pass.
_Avoid_: Limitations, caveats, not tested

**Flow step**:
One message in a protocol exchange, carrying a provenance and the findings that concern it.
_Avoid_: Arrow, hop, stage

**Report**:
The findings and flow steps for a workspace at an evaluation instant.
_Avoid_: Result, output, scan

### Delivery

**Engine**:
The part that turns a workspace into a report, identical wherever it runs.
_Avoid_: Core, backend, library

**Proxy**:
The hosted service that fetches public documents and sends probes on behalf of the web interface.
It never handles a credential.
_Avoid_: Backend, API, server

**Credential**:
Anything that grants access to a target or decrypts its messages: a client secret, a bearer token, an authorization code, a code verifier, or a private key.
_Avoid_: Secret, token as a catch-all
