import { execFile } from 'node:child_process';
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
