import { execFile } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
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

/** A real ID token, signed by Keycloak for its bootstrap administrator. */
async function idToken(): Promise<string> {
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
  return (await response.json()).id_token;
}

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

  await inspect(page, token);
  await expect(page.locator('.results-head h2')).toHaveText(`OIDC ${REALM}`);
  await expect(finding(page, 'oidc.id-token.signature').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.id-token.signature')).toContainText('verifies with RS256');
  await expect(finding(page, 'oidc.id-token.issuer').locator('.badge')).toHaveText('pass');
  await expect(finding(page, 'oidc.id-token.key').locator('.badge')).toHaveText('pass');

  // The token is read here: it reaches neither the address bar nor the proxy.
  expect(page.url()).not.toContain('target');
  expect(requested.some((url) => url.includes('/api/fetch'))).toBe(true);
  expect(requested.join('\n')).not.toContain(token.split('.')[2]);

  // The evidence shows what the token says, not its encoded form.
  const evidence = page.locator('.evidence', { hasText: 'oidc.id-token' });
  await evidence.locator('summary').click();
  await expect(evidence.locator('pre')).toContainText(`"iss": "${REALM}"`);
});

test('refuses a token whose claims were changed after it was signed', async ({ page }) => {
  await inspect(page, altered(await idToken()));
  await expect(finding(page, 'oidc.id-token.signature').locator('.badge')).toHaveText('error');
  await expect(finding(page, 'oidc.id-token.signature')).toContainText('does not verify');
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
  const signature = findings.find(
    (f: { checkId: string }) => f.checkId === 'oidc.id-token.signature',
  );
  expect(signature).toMatchObject({ severity: 'pass', provenance: 'user-supplied' });
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
