import { execFile } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { promisify } from 'node:util';
import { expect, type Page, test } from '@playwright/test';

const KEYCLOAK = process.env.KEYCLOAK_URL ?? 'http://localhost:8089';
const REALM = `${KEYCLOAK}/realms/master`;
const run = promisify(execFile);

const METADATA = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example/metadata">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

async function inspect(page: Page, target: string) {
  await page.goto('/');
  await page.getByLabel('Target').fill(target);
  await page.getByRole('button', { name: 'Inspect' }).click();
  await expect(page.locator('.results')).toBeVisible();
}

const finding = (page: Page, checkId: string) =>
  page.locator('.finding', { has: page.getByText(checkId, { exact: true }) });

test('inspects a live OpenID Provider and reports what it publishes', async ({ page }) => {
  await inspect(page, REALM);

  await expect(page.locator('.results-head h2')).toHaveText(`OIDC ${REALM}`);
  // A development Keycloak serves plain http, which is a real defect to report.
  await expect(finding(page, 'oidc.discovery.issuer-form')).toContainText('scheme is http');
  await expect(finding(page, 'oidc.discovery.issuer-match').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.jwks.reachable').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.discovery.pkce-s256')).toContainText('S256 is advertised');
});

test('marks every flow step as unperformed and narrows findings to a selected step', async ({
  page,
}) => {
  await inspect(page, REALM);

  const steps = page.locator('.flow .step');
  await expect(steps).toHaveCount(5);
  await expect(page.locator('.flow .step.illustrative')).toHaveCount(5);

  const all = await page.locator('.finding').count();
  await steps.nth(3).click();
  await expect(page.locator('.step-detail')).toContainText(
    `${REALM}/protocol/openid-connect/certs`,
  );
  await expect(finding(page, 'oidc.jwks.reachable')).toBeVisible();
  await expect(finding(page, 'oidc.discovery.password-grant')).toHaveCount(0);
  expect(await page.locator('.finding').count()).toBeLessThan(all);
});

test('detects SAML metadata from a URL that serves it', async ({ page }) => {
  await inspect(page, `${REALM}/protocol/saml/descriptor`);

  await expect(page.locator('.results-head .tag')).toHaveText('SAML');
  await expect(finding(page, 'saml.idp.signing-key').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'saml.cert.key-strength')).toContainText('2048');
  await expect(finding(page, 'saml.metadata.endpoints-https').locator('.badge')).toHaveText(
    'error',
  );
});

test('parses pasted metadata in the browser without sending it anywhere', async ({ page }) => {
  const requests: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/')) requests.push(request.url());
  });
  await inspect(page, METADATA);

  await expect(page.locator('.results-head .tag')).toHaveText('SAML');
  await expect(finding(page, 'saml.sp.want-assertions-signed').locator('.badge')).toHaveText(
    'warn',
  );
  await expect(finding(page, 'saml.sp.acs').locator('.tag.provenance')).toHaveText('user-supplied');
  expect(requests).toEqual([]);
  expect(page.url()).not.toContain('EntityDescriptor');
});

test('judges time-bounded evidence at the chosen instant', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Target').fill(`${REALM}/protocol/saml/descriptor`);
  await page.getByLabel('Evaluate as of').fill('2099-01-01T00:00');
  await page.getByRole('button', { name: 'Inspect' }).click();

  await expect(finding(page, 'saml.cert.validity')).toContainText('expired');
});

test('inspects a bare three-part hostname as a provider, not as a token', async ({ page }) => {
  await inspect(page, 'nothing.example.invalid');
  await expect(page.locator('.results-head h2')).toHaveText('OIDC https://nothing.example.invalid');
  await expect(finding(page, 'oidc.discovery.reachable').locator('.badge')).toHaveText('error');
});

test('reports an unreachable target instead of failing', async ({ page }) => {
  await inspect(page, 'http://localhost:9/realms/none');
  await expect(finding(page, 'oidc.discovery.reachable').locator('.badge')).toHaveText('error');

  // The overview has nothing to restate, and says which document is the reason.
  await page.getByRole('tab', { name: 'What it publishes' }).click();
  await expect(page.locator('.overview .unread')).toContainText(
    'http://localhost:9/realms/none/.well-known/openid-configuration',
  );
});

test('judges a server with no OpenID configuration as an OAuth authorization server', async ({
  page,
}) => {
  // A plain authorization server: RFC 8414 metadata and nothing at the OpenID path.
  const server = createServer((request, response) => {
    const { port } = server.address() as AddressInfo;
    const issuer = `http://localhost:${port}`;
    if (request.url !== '/.well-known/oauth-authorization-server') {
      response.writeHead(404, { 'content-type': 'text/html' }).end('<h1>Not Found</h1>');
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' }).end(
      JSON.stringify({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
      }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const issuer = `http://localhost:${(server.address() as AddressInfo).port}`;
  try {
    await inspect(page, issuer);

    await expect(page.locator('.results-head h2')).toHaveText(`OAUTH ${issuer}`);
    await expect(finding(page, 'oauth.metadata.openid-discovery')).toContainText(
      'consistent for a plain OAuth 2.0 authorization server',
    );
    await expect(finding(page, 'oauth.metadata.issuer-form')).toContainText('scheme is http');
    await expect(finding(page, 'oauth.metadata.issuer-form')).toContainText(
      'If you run the authorization server',
    );
    await page.screenshot({
      fullPage: true,
    });
    await expect(finding(page, 'oauth.metadata.pkce-s256')).toContainText('S256 is advertised');
    // Nothing here is an OpenID Provider, so nothing is held to the rules for one.
    await expect(page.locator('.finding', { hasText: 'oidc.discovery.' })).toHaveCount(0);

    // No keys are published, so the flow stops at the token: there is no ID token to verify.
    await expect(page.locator('.flow .step')).toHaveCount(3);
    await expect(page.locator('.flow .lane-name')).toHaveText(['Browser', 'Client', 'AS']);

    await page.getByRole('tab', { name: 'What it publishes' }).click();
    await expect(page.locator('.overview')).toContainText('Authorization server');
    await expect(page.locator('.overview')).toContainText(
      `${issuer}/.well-known/oauth-authorization-server`,
    );
  } finally {
    server.close();
  }
});

test('says what no published document can show, beside what the target publishes', async ({
  page,
}) => {
  await inspect(page, REALM);
  await page.getByRole('tab', { name: 'What it publishes' }).click();
  const unseen = page.locator('.overview .unseen');
  await expect(unseen).toContainText('Not visible in what it publishes');
  await expect(unseen.locator('li')).toHaveCount(6);
  await expect(unseen).toContainText('Whether refresh tokens are rotated');
  await page.screenshot({
    fullPage: true,
  });

  // Nothing was read from an unreachable target, so there is nothing to qualify.
  await inspect(page, 'http://localhost:9/realms/none');
  await page.getByRole('tab', { name: 'What it publishes' }).click();
  await expect(page.locator('.overview .unseen')).toHaveCount(0);
});

test('opens a shared link straight into its report', async ({ page }) => {
  await page.goto(`/?target=${encodeURIComponent(REALM)}&protocol=oidc`);
  await expect(page.locator('.results-head h2')).toHaveText(`OIDC ${REALM}`);
  await expect(page.getByLabel('Target')).toHaveValue(REALM);
});

test('the CLI reaches the same verdicts and fails the build on errors', async () => {
  const outcome = await run('node', [
    'packages/cli/dist/main.js',
    'inspect',
    REALM,
    '--format',
    'json',
  ]).catch((error: { code: number; stdout: string }) => error);
  expect('code' in outcome ? outcome.code : 0).toBe(1);
  const report = JSON.parse(outcome.stdout);
  expect(report.target).toEqual({ protocol: 'oidc', input: REALM });
  expect(
    report.findings.find((f: { checkId: string }) => f.checkId === 'oidc.discovery.issuer-form')
      .severity,
  ).toBe('error');
});

/** Real tokens, signed by Keycloak for its bootstrap administrator. */
async function tokens(): Promise<{ id_token: string; access_token: string }> {
  const response = await fetch(`${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: 'admin',
      password: 'admin',
      scope: 'openid',
    }),
  });
  return response.json();
}

const idToken = async () => (await tokens()).id_token;

/** The same token with one claim changed and the original signature kept. */
function altered(token: string): string {
  const [header, payload = '', signature] = token.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  const forged = Buffer.from(JSON.stringify({ ...claims, sub: 'someone-else' }));
  return `${header}.${forged.toString('base64url')}.${signature}`;
}

test('verifies a pasted ID token against the keys its issuer publishes', async ({ page }) => {
  const token = await idToken();
  const requested: string[] = [];
  page.context().on('request', (request) => requested.push(request.url()));

  await page.goto('/');
  await page.getByLabel('Target').fill(token);
  await expect(page.locator('.trust')).toContainText('This ID token is read in this browser');

  await inspect(page, token);
  await expect(page.locator('.results-head h2')).toHaveText(`OIDC ID token ${REALM}`);
  await expect(finding(page, 'oidc.token.signature').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.token.signature')).toContainText('verifies with RS256');
  await expect(finding(page, 'oidc.token.issuer').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.token.key').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.token.kind')).toContainText('judged as an ID token');

  // The token is read here: it reaches neither the address bar nor the proxy.
  expect(page.url()).not.toContain('target');
  expect(requested.some((url) => url.includes('/api/fetch'))).toBe(true);
  expect(requested.join('\n')).not.toContain(token.split('.')[2]);

  // The evidence shows what the token says, not its encoded form.
  const evidence = page.locator('.evidence', { hasText: 'oidc.token' });
  await evidence.locator('summary').click();
  await expect(evidence.locator('pre')).toContainText(`"iss": "${REALM}"`);
});

test('judges a pasted access token as one, by its own rules', async ({ page }) => {
  await inspect(page, (await tokens()).access_token);
  await expect(page.locator('.results-head h2')).toHaveText(`OIDC access token ${REALM}`);
  await expect(finding(page, 'oidc.token.kind')).toContainText('judged as an access token');
  await expect(finding(page, 'oidc.token.signature').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.access-token.required-claims')).toBeVisible();
  await expect(finding(page, 'oidc.id-token.required-claims')).toHaveCount(0);

  await page.getByRole('tab', { name: 'What it publishes' }).click();
  await expect(page.locator('.overview')).toContainText('Pasted access token');
});

test('refuses a token whose claims were changed after it was signed', async ({ page }) => {
  await inspect(page, altered(await idToken()));
  await expect(finding(page, 'oidc.token.signature').locator('.badge')).toHaveText('error');
  await expect(finding(page, 'oidc.token.signature')).toContainText('does not verify');
});

test('the CLI verifies an ID token read from a file', async () => {
  const file = test.info().outputPath('id-token.jwt');
  await writeFile(file, `${await idToken()}\n`);
  const outcome = await run('node', [
    'packages/cli/dist/main.js',
    'inspect',
    file,
    '--format',
    'json',
  ]).catch((error: { stdout: string }) => error);
  const { findings } = JSON.parse(outcome.stdout);
  const signature = findings.find((f: { checkId: string }) => f.checkId === 'oidc.token.signature');
  expect(signature).toMatchObject({ severity: 'pass', provenance: 'user-supplied' });
});

const SAML_METADATA = `${REALM}/protocol/saml/descriptor`;

/**
 * A real SAML response: Keycloak signs in its administrator to a SAML client and
 * posts the result to an ACS that exists only as a route in this browser.
 * Returned exactly as the browser posted it, base64 and URL-encoded.
 */
async function samlResponse(page: Page): Promise<string> {
  const { access_token } = await tokens();
  // 409 means an earlier run already registered the client, which is fine.
  await fetch(`${KEYCLOAK}/admin/realms/master/clients`, {
    method: 'POST',
    headers: { authorization: `Bearer ${access_token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      clientId: 'https://sp.example/metadata',
      protocol: 'saml',
      redirectUris: ['https://sp.example/*'],
      attributes: {
        saml_idp_initiated_sso_url_name: 'idi-e2e',
        saml_assertion_consumer_url_post: 'https://sp.example/acs',
        'saml.assertion.signature': 'true',
        'saml.server.signature': 'true',
        'saml.client.signature': 'false',
      },
    }),
  });

  let posted = '';
  await page.route('https://sp.example/**', (route) => {
    posted = new URLSearchParams(route.request().postData() ?? '').get('SAMLResponse') ?? '';
    return route.fulfill({ status: 200, body: 'received' });
  });
  await page.goto(`${REALM}/protocol/saml/clients/idi-e2e`);
  await page.locator('#username').fill('admin');
  await page.locator('#password').fill('admin');
  await page.locator('#kc-login').click();
  await expect(page.getByText('received')).toBeVisible();
  return encodeURIComponent(posted);
}

/** The same response with the user changed and the original signatures kept. */
function alteredResponse(posted: string): string {
  const xml = Buffer.from(decodeURIComponent(posted), 'base64').toString();
  return Buffer.from(xml.replace(/(<saml:NameID[^>]*>)[^<]+/, '$1someone-else')).toString('base64');
}

test('verifies a pasted SAML response against the metadata its IdP publishes', async ({ page }) => {
  const posted = await samlResponse(page);
  const requested: string[] = [];
  page.context().on('request', (request) => requested.push(request.url()));

  await page.goto('/');
  await page.getByLabel('Target').fill(posted);
  await page.getByLabel('IdP metadata (optional)').fill(SAML_METADATA);
  await page.getByRole('button', { name: 'Inspect' }).click();
  await expect(page.locator('.results')).toBeVisible();

  await expect(page.locator('.results-head h2')).toHaveText(`SAML response ${REALM}`);
  const signature = finding(page, 'saml.response.signature');
  await expect(signature).toHaveCount(2);
  await expect(signature.locator('.badge')).toHaveText(['pass', 'pass']);
  await expect(signature.first()).toContainText('that the IdP publishes');
  await expect(finding(page, 'saml.response.status').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'saml.response.issuer').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'saml.response.signature-reference').locator('.badge')).toHaveText([
    'pass',
    'pass',
  ]);

  // The response is read here: only the metadata URL goes to the proxy.
  expect(page.url()).not.toContain('target');
  const fetched = requested.filter((url) => url.includes('/api/fetch'));
  expect(fetched).toEqual([expect.stringContaining(encodeURIComponent(SAML_METADATA))]);

  await page.getByRole('tab', { name: 'What it publishes' }).click();
  await expect(page.locator('.overview')).toContainText('Pasted response');
  await expect(page.locator('.overview')).toContainText('https://sp.example/acs');
});

test('says a SAML response without metadata is consistent, not who signed it', async ({ page }) => {
  await inspect(page, await samlResponse(page));
  const signature = finding(page, 'saml.response.signature').first();
  await expect(signature.locator('.badge')).toHaveText('info');
  await expect(signature).toContainText('does not show who signed it');
});

test('refuses a SAML response whose subject was changed after it was signed', async ({ page }) => {
  const forged = alteredResponse(await samlResponse(page));
  await page.goto('/');
  await page.getByLabel('Target').fill(forged);
  await page.getByLabel('IdP metadata (optional)').fill(SAML_METADATA);
  await page.getByRole('button', { name: 'Inspect' }).click();
  const signature = finding(page, 'saml.response.signature');
  await expect(signature.locator('.badge')).toHaveText(['error', 'error']);
  await expect(signature.first()).toContainText('changed after it was signed');
});

test('the CLI verifies a SAML response read from a file', async ({ page }) => {
  const file = test.info().outputPath('response.b64');
  await writeFile(file, decodeURIComponent(await samlResponse(page)));
  const outcome = await run('node', [
    'packages/cli/dist/main.js',
    'inspect',
    file,
    '--metadata',
    SAML_METADATA,
    '--format',
    'json',
  ]).catch((error: { stdout: string }) => error);
  const { findings } = JSON.parse(outcome.stdout);
  const signatures = findings.filter(
    (f: { checkId: string }) => f.checkId === 'saml.response.signature',
  );
  expect(signatures.map((f: { severity: string }) => f.severity)).toEqual(['pass', 'pass']);
});

test('restates what the target publishes on its own tab, without verdicts', async ({ page }) => {
  await inspect(page, REALM);
  await page.getByRole('tab', { name: 'What it publishes' }).click();

  const overview = page.locator('.overview');
  await expect(overview.getByText('Token', { exact: true })).toBeVisible();
  await expect(overview).toContainText(`${REALM}/protocol/openid-connect/token`);
  await expect(overview).toContainText('S256');
  await expect(page.locator('.finding')).toHaveCount(0);
  await expect(page.locator('.filters')).toHaveCount(0);

  await page.getByRole('tab', { name: /Findings/ }).click();
  await expect(page.locator('.finding').first()).toBeVisible();
});

test('a severity chip shows that severity alone until it is pressed again', async ({ page }) => {
  await inspect(page, REALM);
  const all = await page.locator('.finding').count();
  const pass = page.getByRole('button', { name: /\d+ pass$/ });

  await pass.click();
  await expect(pass).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.finding .badge.pass').first()).toBeVisible();
  await expect(page.locator('.finding .badge:not(.pass)')).toHaveCount(0);

  // Choosing another severity replaces the first instead of adding to it.
  await page.getByRole('button', { name: /\d+ warn$/ }).click();
  await expect(pass).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('.finding .badge:not(.warn)')).toHaveCount(0);

  await page.getByRole('button', { name: /\d+ warn$/ }).click();
  await expect(page.locator('.finding')).toHaveCount(all);
});

test('shows fetched evidence indented with its member names set apart', async ({ page }) => {
  await inspect(page, REALM);
  const evidence = page.locator('.evidence').first();
  await evidence.locator('summary').click();
  await expect(evidence.locator('pre b').first()).toHaveText('"issuer"');
  await expect(evidence.locator('pre')).toContainText(`"issuer": "${REALM}"`);
});

test('starts light whatever the system prefers, and remembers a switch to dark', async ({
  browser,
}) => {
  const context = await browser.newContext({ colorScheme: 'dark' });
  const page = await context.newPage();
  const background = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);

  await page.goto('/');
  expect(await background()).toBe('rgb(255, 255, 255)');

  await page.getByRole('button', { name: 'Dark theme' }).click();
  expect(await background()).toBe('rgb(11, 13, 20)');

  await page.reload();
  expect(await background()).toBe('rgb(11, 13, 20)');
  await expect(page.getByRole('button', { name: 'Dark theme' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  await context.close();
});

test('lays the results out without a scroll area nested inside the page', async ({ page }) => {
  await inspect(page, REALM);
  const nested = await page.evaluate(
    () =>
      [...document.querySelectorAll('.columns, .columns > *')].filter((el) => {
        const { overflowY } = getComputedStyle(el);
        return overflowY === 'auto' || overflowY === 'scroll';
      }).length,
  );
  expect(nested).toBe(0);
});

test('returns to the empty home screen from the brand', async ({ page }) => {
  await inspect(page, REALM);
  await page.getByRole('link', { name: 'Identity Inspector home' }).click();

  await expect(page.locator('.results')).toHaveCount(0);
  await expect(page.getByLabel('Target')).toHaveValue('');
  await expect(page.getByText('Try a public target')).toBeVisible();
  expect(new URL(page.url()).search).toBe('');
});

test('offers a public target to try for every protocol', async ({ page }) => {
  await page.goto('/');
  const kinds = await page.locator('.examples .tag').allInnerTexts();
  expect(new Set(kinds)).toEqual(new Set(['OIDC', 'OAUTH', 'SAML', 'SCIM']));

  // Choosing one fills the target and names it in a link that can be shared.
  await page.getByRole('button', { name: /api\.slack\.com\/scim\/v2/ }).click();
  await expect(page.getByLabel('Target')).toHaveValue('https://api.slack.com/scim/v2');
  expect(new URL(page.url()).searchParams.get('target')).toBe('https://api.slack.com/scim/v2');
});

test('explains how to use it until there is a report to read instead', async ({ page }) => {
  await page.goto('/');
  const guide = page.locator('.guide');
  await expect(guide.getByRole('heading', { level: 3 })).toHaveText([
    'Give it a target',
    'Read the findings',
    'Take it further',
  ]);
  // Every protocol the picker offers is explained.
  await expect(guide.locator('dt')).toHaveText(['OIDC', 'OAUTH', 'SAML', 'SCIM']);

  await inspect(page, REALM);
  await expect(guide).toHaveCount(0);
});

test('keeps the example targets inside their card on a phone', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await page.goto('/');
  const card = await page.locator('.empty > div').first().boundingBox();
  for (const button of await page.locator('.examples button').all()) {
    const box = await button.boundingBox();
    expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(
      (card?.x ?? 0) + (card?.width ?? 0),
    );
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});
