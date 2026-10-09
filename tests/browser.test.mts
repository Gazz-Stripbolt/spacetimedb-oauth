// End-to-end browser tests: the demo page in headless Chromium, linking through real popups and
// redirects against the mock provider.
//
//   PAGE=http://127.0.0.1:3000/v1/database/oauth-rust/route/ MOCK=http://127.0.0.1:4110 npx tsx tests/browser.test.mts
//
// SHOTS=<dir> also saves light and dark screenshots of the linked state.
import assert from 'node:assert/strict';
import { chromium, type Browser, type Page } from 'playwright';

const PAGE = process.env.PAGE ?? 'http://127.0.0.1:3000/v1/database/oauth-rust/route/';
const MOCK = process.env.MOCK ?? 'http://127.0.0.1:4110';
const SHOTS = process.env.SHOTS;
const origin = new URL(PAGE).origin;

let passed = 0;
async function test(name: string, fn: () => Promise<void>) {
  await fn();
  passed++;
  console.log(`  ok  ${name}`);
}

async function open(browser: Browser, scheme: 'light' | 'dark' = 'light'): Promise<Page> {
  const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: 1100, height: 900 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.error('[page]', e.message));
  await page.goto(`${PAGE}${PAGE.includes('?') ? '&' : '?'}test=1&fresh=1&api=${encodeURIComponent(`${MOCK}/api/me`)}`);
  await page.waitForFunction(() => document.querySelector('#status')?.textContent?.startsWith('connected'));
  return page;
}

/** Click "Link", approve as `who` in the popup, and wait for the account row. */
async function linkInPopup(page: Page, who: string) {
  const [popup] = await Promise.all([page.context().waitForEvent('page'), page.click('#link')]);
  await popup.waitForURL(`${MOCK}/authorize?**`);
  await popup.click(`text=@${who}`);
  await popup.waitForEvent('close', { timeout: 10_000 });
  await page.waitForSelector(`.account .who:has-text("${who}")`);
}

const browser = await chromium.launch();
try {
  const page = await open(browser);

  await test('popup flow: consent in a popup, the popup closes, the account appears', async () => {
    await linkInPopup(page, 'alice');
    const meta = await page.textContent('.account .meta');
    assert.match(meta!, /mock · id 1001 · scopes profile api/);
    assert.match((await page.textContent('#log'))!, /linked\s+mock as alice/);
  });

  await test('call the API through the module with the linked token', async () => {
    await page.click('text=Call API');
    await page.waitForFunction(() => document.querySelector('#api')?.textContent?.includes('preferred_username'));
    assert.equal(JSON.parse((await page.textContent('#api'))!).preferred_username, 'alice');
  });

  await test("shared-origin safety: a page on the same host but outside the app URLs doesn't get the code", async () => {
    // Another "app" on the same origin (on Maincloud: any other database's routes).
    const other = await page.context().newPage();
    await other.goto(`${origin}/v1/ping`);
    const url = await page.evaluate(() => (window as any).__api.begin('mock'));
    await other.evaluate(() => {
      (window as any).__got = [];
      addEventListener('message', (e) => (window as any).__got.push(e.data));
    });
    const [popup] = await Promise.all([other.context().waitForEvent('page'), other.evaluate((u) => void window.open(u, 'x', 'popup'), url)]);
    await popup.waitForURL(`${MOCK}/authorize?**`);
    await popup.click('text=@alice');
    await popup.waitForURL(/oauth\/callback/);
    await popup.waitForSelector('text=Return to the app');
    await other.waitForTimeout(300);
    assert.deepEqual(await other.evaluate(() => (window as any).__got), []);
    await popup.close();
    await other.close();
  });

  await test('redirect flow: the whole page goes to the provider and comes back linked', async () => {
    await page.click('#link-redirect');
    await page.waitForURL(`${MOCK}/authorize?**`);
    await page.click('text=@bob');
    await page.waitForSelector('.account .who:has-text("bob")');
    assert.equal(new URL(page.url()).hash, '', 'the fragment was cleaned up');
    assert.match((await page.textContent('#log'))!, /linked\s+mock as bob \(redirect mode\)/);
    assert.equal(await page.locator('.account').count(), 1, 're-linking replaced alice');
  });

  await test('a closed popup is reported, not hung on', async () => {
    const [popup] = await Promise.all([page.context().waitForEvent('page'), page.click('#link')]);
    await popup.waitForURL(`${MOCK}/authorize?**`);
    await popup.close();
    await page.waitForFunction(() => document.querySelector('#log')?.textContent?.includes('the sign-in window was closed'));
  });

  await test('unlink removes the account', async () => {
    await page.click('text=Unlink');
    await page.waitForSelector('text=Nothing linked yet.');
  });

  if (SHOTS) {
    for (const scheme of ['light', 'dark'] as const) {
      const p = await open(browser, scheme);
      await linkInPopup(p, 'alice');
      await p.click('text=Call API');
      await p.waitForFunction(() => document.querySelector('#api')?.textContent?.includes('preferred_username'));
      await p.screenshot({ path: `${SHOTS}/demo-${scheme}.png`, fullPage: true });
      await p.evaluate(() => (window as any).__api.unlink('mock'));
    }
  }
} finally {
  await browser.close();
}
console.log(`\n${passed} passed`);
