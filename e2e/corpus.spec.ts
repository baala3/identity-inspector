import { expect, test } from '@playwright/test';
import { collect, evaluate } from '../packages/core/dist/index.js';
import {
  identity,
  metadataFor,
  plainAssertion,
  plainResponse,
  sign,
} from '../packages/core/test/support/saml.js';

// ADR 0002: adversarial input must get the same verdict from the engine in Node
// and from the engine in a real browser. A difference between the two is the bug
// this corpus exists to catch, whatever the verdict is.

const idp = identity('idp.example', ['-newkey', 'rsa:2048']);
const stranger = identity('stranger.example', ['-newkey', 'rsa:2048']);
const METADATA = metadataFor(idp);

const GENUINE = sign(plainResponse(plainAssertion('_a1', 'user@example.com')), idp, {
  element: 'Assertion',
});
const [SIGNED_ASSERTION = ''] = /<saml:Assertion[\s\S]*<\/saml:Assertion>/.exec(GENUINE) ?? [];
const FORGED = plainAssertion('_evil', 'admin@example.com');

/** Each case names the verdict the signature checks must reach, in both environments. */
const CORPUS: Array<{ name: string; xml: string; expected: Record<string, string[]> }> = [
  {
    name: 'a genuine response',
    xml: GENUINE,
    expected: {
      'saml.response.signature-reference': ['pass'],
      'saml.response.signature': ['pass'],
    },
  },
  {
    name: 'a subject changed after signing',
    xml: GENUINE.replace('user@example.com', 'admin@example.com'),
    expected: { 'saml.response.signature': ['error'] },
  },
  {
    name: 'a forged assertion that keeps the signature of the original, hidden beside it',
    xml: plainResponse(
      SIGNED_ASSERTION.replace('ID="_a1"', 'ID="_evil"').replace('user@', 'admin@'),
      `<samlp:Extensions>${SIGNED_ASSERTION}</samlp:Extensions>`,
    ),
    expected: { 'saml.response.signature-reference': ['error'], 'saml.response.signature': [] },
  },
  {
    name: 'a second element taking the signed ID',
    xml: GENUINE.replace('</samlp:Response>', '<saml:Advice ID="_a1"/></samlp:Response>'),
    expected: { 'saml.response.signature-reference': ['error'], 'saml.response.signature': [] },
  },
  {
    name: 'an unsigned forged assertion placed ahead of the signed one',
    xml: plainResponse(FORGED + SIGNED_ASSERTION),
    expected: { 'saml.response.signed': ['error'], 'saml.assertion.readable': ['warn'] },
  },
  {
    name: 'a signed assertion wrapped inside an unsigned forged one',
    xml: plainResponse(
      FORGED.replace(
        '</saml:Assertion>',
        `<saml:Advice>${SIGNED_ASSERTION}</saml:Advice></saml:Assertion>`,
      ),
    ),
    expected: { 'saml.response.signed': ['error'] },
  },
  {
    name: 'a comment splitting the signed subject',
    xml: sign(plainResponse(plainAssertion('_a1', 'user@example.com.evil.test')), idp, {
      element: 'Assertion',
    }).replace('user@example.com.evil.test', 'user@example.com<!---->.evil.test'),
    expected: { 'saml.response.signature': ['pass'] },
  },
  {
    name: 'a response signed by someone the IdP does not publish',
    xml: sign(plainResponse(plainAssertion('_a1', 'user@example.com')), stranger, {
      element: 'Assertion',
    }),
    expected: { 'saml.response.signature': ['error'] },
  },
  {
    name: 'a response that declares an entity',
    xml: `<!DOCTYPE r [<!ENTITY who "admin@example.com">]>${GENUINE}`,
    expected: { 'saml.response.well-formed': ['error'], 'saml.response.signature': [] },
  },
];

const verdicts = (findings: Array<{ checkId: string; severity: string }>) =>
  findings
    .filter(
      (f) => f.checkId.startsWith('saml.response.') || f.checkId.startsWith('saml.assertion.'),
    )
    .map((f) => `${f.checkId} ${f.severity}`)
    .sort();

for (const { name, xml, expected } of CORPUS) {
  test(`${name} gets one verdict in Node and in the browser`, async ({ page }) => {
    const never = async () => {
      throw new Error('the corpus must not need the network');
    };
    const workspace = await collect(xml, never, { samlMetadata: METADATA });
    const inNode = await evaluate(workspace);

    await page.goto('/');
    await page.getByLabel('Target').fill(xml);
    const metadata = page.getByLabel('IdP metadata (optional)');
    if (await metadata.isVisible()) await metadata.fill(METADATA);
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Inspect' }).click();
    await expect(page.locator('.results')).toBeVisible();
    await page.getByRole('button', { name: 'JSON' }).click();
    const inBrowser = JSON.parse(
      await (await (await download).createReadStream())
        .toArray()
        .then((c) => Buffer.concat(c).toString()),
    );

    expect(verdicts(inBrowser.findings)).toEqual(verdicts(inNode.findings));
    for (const [checkId, severities] of Object.entries(expected)) {
      expect(
        inNode.findings.filter((f) => f.checkId === checkId).map((f) => f.severity),
        checkId,
      ).toEqual(severities);
    }
  });
}

test('shows the whole subject when a comment splits it, as the signature covers it', async ({
  page,
}) => {
  const split = CORPUS.find((c) => c.name.startsWith('a comment'))?.xml ?? '';
  await page.goto('/');
  await page.getByLabel('Target').fill(split);
  await page.getByRole('button', { name: 'Inspect' }).click();
  await page.getByRole('tab', { name: 'What it publishes' }).click();
  await expect(page.locator('.overview')).toContainText('user@example.com.evil.test');
});
