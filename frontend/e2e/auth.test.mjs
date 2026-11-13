import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { after, afterEach, before, beforeEach, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const root = fileURLToPath(new URL('../../', import.meta.url));
const python = process.env.PYTHON || (existsSync(join(root, '.venv/bin/python'))
  ? join(root, '.venv/bin/python') : 'python3');
const email = 'browser-test@example.com';
const password = randomBytes(24).toString('base64url');
let server, browser, directory, origin, context, page;
let browserErrors = [];

describe('Aufgabe 2: Angular and Python together', () => {
  before(async () => {
    assert.ok(existsSync(join(root, 'frontend/dist/audittrail/browser/index.html')), 'Run npm run build first');
    directory = await mkdtemp(join(tmpdir(), 'audittrail-e2e-'));
    const socket = createServer();
    socket.listen(0, '127.0.0.1');
    await once(socket, 'listening');
    const port = socket.address().port;
    await new Promise(resolve => socket.close(resolve));
    origin = `http://127.0.0.1:${port}`;

    const hash = spawnSync(python, ['-c',
      'import sys; from backend.security import hash_password; print(hash_password(sys.stdin.read()))',
    ], { cwd: root, input: password, encoding: 'utf8' });
    assert.equal(hash.status, 0, hash.stderr);
    server = spawn(python, ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', String(port)], {
      cwd: root,
      env: { ...process.env, APP_ORIGIN: origin, AUDITTRAIL_EMAIL: email,
        AUDITTRAIL_PASSWORD_HASH: hash.stdout.trim(), SESSION_DB: join(directory, 'sessions.sqlite3') },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let logs = '';
    server.stdout.on('data', data => { logs = (logs + data).slice(-8000); });
    server.stderr.on('data', data => { logs = (logs + data).slice(-8000); });
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      try { ready = (await fetch(origin + '/health')).ok; } catch {}
      if (ready || server.exitCode !== null) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(ready, 'Backend did not become ready: ' + logs);
    browser = await chromium.launch({ headless: true });
  });

  after(async () => {
    await browser?.close();
    if (server && server.exitCode === null) {
      const exited = once(server, 'exit');
      server.kill();
      await exited;
    }
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  beforeEach(async () => {
    browserErrors = [];
    context = await browser.newContext({ baseURL: origin });
    await context.addInitScript(() => {
      window.securityViolations = [];
      document.addEventListener('securitypolicyviolation', event =>
        window.securityViolations.push(event.violatedDirective));
    });
    page = await context.newPage();
    page.on('pageerror', error => browserErrors.push(error.message));
    await page.goto('/');
    await page.getByRole('button', { name: 'Test protected endpoint' }).waitFor();
  });

  afterEach(async () => {
    try {
      assert.deepEqual(browserErrors, [], 'Browser runtime errors');
      assert.deepEqual(await page.evaluate(() => window.securityViolations), [], 'CSP violations');
    } finally {
      await context?.close();
    }
  });

  async function signIn() {
    await page.getByLabel('Email', { exact: true }).fill(email);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('button', { name: 'Sign out', exact: true }).waitFor();
  }

  test('denies anonymous access, signs in, restores, reads documents, and signs out', async () => {
    await page.getByRole('button', { name: 'Test protected endpoint' }).click();
    await page.getByText('Access denied. The document endpoint is protected.').waitFor();
    assert.equal((await page.request.get('/api/documents')).status(), 401);

    await signIn();
    await page.getByRole('button', { name: 'Load documents' }).click();
    await page.getByText('Access granted. 0 document(s) returned.').waitFor();
    const oldCookie = (await context.cookies()).find(cookie => cookie.name === 'audittrail_session');
    assert.ok(oldCookie);

    await page.reload();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('button', { name: 'Test protected endpoint' }).click();
    await page.getByText('Access denied. The document endpoint is protected.').waitFor();
    assert.equal((await context.cookies()).length, 0);
    const replay = await browser.newContext({ baseURL: origin,
      extraHTTPHeaders: { Cookie: `audittrail_session=${oldCookie.value}` } });
    try { assert.equal((await replay.request.get('/api/documents')).status(), 401); }
    finally { await replay.close(); }
  });

  test('rejects a wrong password and clears the password field', async () => {
    await page.getByLabel('Email', { exact: true }).fill(email);
    await page.getByLabel('Password', { exact: true }).fill('incorrect-password');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('alert').getByText('Incorrect email or password.').waitFor();
    assert.equal(await page.getByLabel('Password', { exact: true }).inputValue(), '');
    assert.equal((await page.request.get('/api/documents')).status(), 401);
  });

  test('logout in another tab invalidates document access', async () => {
    await signIn();
    const other = await context.newPage();
    await other.goto('/');
    await other.getByRole('button', { name: 'Load documents' }).waitFor();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await other.getByRole('button', { name: 'Load documents' }).click();
    await other.getByText('Access denied. Sign in again or check your permissions.').waitFor();
    await other.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
  });

  test('keeps the session cookie out of JavaScript and browser storage', async () => {
    await signIn();
    const cookie = (await context.cookies()).find(cookie => cookie.name === 'audittrail_session');
    assert.ok(cookie.httpOnly);
    assert.equal(cookie.sameSite, 'Lax');
    assert.equal(await page.evaluate(() => document.cookie), '');
    assert.deepEqual(await page.evaluate(() => ({
      local: Object.keys(localStorage), session: Object.keys(sessionStorage),
    })), { local: [], session: [] });
  });

  test('renders malicious document names as text', async () => {
    await signIn();
    const name = '<img src=x onerror="window.audittrailXss=true">';
    await page.route('**/api/documents', route => route.fulfill({
      json: [{ id: 'xss-check', name }],
    }));
    await page.getByRole('button', { name: 'Load documents' }).click();
    await page.getByText(name, { exact: true }).waitFor();
    assert.equal(await page.locator('.documents img').count(), 0);
    assert.equal(await page.evaluate(() => window.audittrailXss), undefined);
  });

  test('keeps login usable on a narrow screen with loaded theme styles', async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    const styles = await page.locator('.login-main').evaluate(element => ({
      display: getComputedStyle(element).display,
      overflow: document.documentElement.scrollWidth > window.innerWidth,
    }));
    assert.equal(styles.display, 'grid', 'The production stylesheet must load under CSP');
    assert.equal(styles.overflow, false);
    await signIn();
  });
});
