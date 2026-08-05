import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { RegistryClient, RegistryError } from '../src/common/registry.js';

const servers = [];

function startMockRegistry(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      servers.push(server);
      resolve({ server, url: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

after(() => {
  for (const s of servers) s.close();
});

function makeClient(url, over = {}) {
  return new RegistryClient({
    registryUrl: url,
    packageName: 'my-package',
    token: 'test-token',
    timeoutMs: 200,
    maxRetries: 0,
    baseDelayMs: 5,
    ...over,
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
}

test('getDistTags returns the tag map and sends no auth requirement on read', async () => {
  const { url } = await startMockRegistry((req, res) => {
    assert.equal(req.method, 'GET');
    assert.equal(req.url, '/-/package/my-package/dist-tags');
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ latest: '1.0.0', 'x-cmd-a-1-Zm9v': '1.0.0' }));
  });
  const client = makeClient(url);
  const tags = await client.getDistTags();
  assert.deepEqual(tags, { latest: '1.0.0', 'x-cmd-a-1-Zm9v': '1.0.0' });
});

test('getDistTags rejects malformed or structurally invalid registry data', async () => {
  const invalidJson = await startMockRegistry((_req, res) => res.end('{broken'));
  await assert.rejects(makeClient(invalidJson.url).getDistTags(), /invalid JSON/);

  const arrayBody = await startMockRegistry((_req, res) => res.end('[]'));
  await assert.rejects(makeClient(arrayBody.url).getDistTags(), /JSON object/);

  const invalidValue = await startMockRegistry((_req, res) => res.end('{"latest":1}'));
  await assert.rejects(makeClient(invalidValue.url).getDistTags(), /string versions/);
});

test('setDistTag issues PUT with bearer token and JSON-string body', async () => {
  let seen = null;
  const { url } = await startMockRegistry(async (req, res) => {
    seen = {
      method: req.method,
      url: req.url,
      auth: req.headers.authorization,
      body: await readBody(req),
    };
    res.setHeader('content-type', 'application/json');
    res.end('{}');
  });
  const client = makeClient(url);
  await client.setDistTag('x-cmd-a1-1-Zm9v', '1.0.0');
  assert.equal(seen.method, 'PUT');
  assert.equal(seen.url, '/-/package/my-package/dist-tags/x-cmd-a1-1-Zm9v');
  assert.equal(seen.auth, 'Bearer test-token');
  assert.equal(seen.body, '"1.0.0"');
});

test('deleteDistTag issues DELETE', async () => {
  let seen = null;
  const { url } = await startMockRegistry((req, res) => {
    seen = { method: req.method, url: req.url, auth: req.headers.authorization };
    res.end('{}');
  });
  const client = makeClient(url);
  await client.deleteDistTag('x-res-a1-1-1of1-Zm9v');
  assert.equal(seen.method, 'DELETE');
  assert.equal(seen.url, '/-/package/my-package/dist-tags/x-res-a1-1-1of1-Zm9v');
  assert.equal(seen.auth, 'Bearer test-token');
});

test('401 produces a clear, non-retriable auth error (no retries)', async () => {
  let requests = 0;
  const { url } = await startMockRegistry((req, res) => {
    requests++;
    res.statusCode = 401;
    res.end(JSON.stringify({ error: 'unauthorized' }));
  });
  const client = makeClient(url, { maxRetries: 3 });
  await assert.rejects(() => client.setDistTag('x-cmd-a-1-Zm9v', '1.0.0'), (err) => {
    assert.ok(err instanceof RegistryError);
    assert.equal(err.status, 401);
    assert.match(err.message, /NPM_C2_TOKEN/);
    return true;
  });
  assert.equal(requests, 1, 'auth errors must not be retried');
});

test('404 produces a clear package-not-found error', async () => {
  const { url } = await startMockRegistry((req, res) => {
    res.statusCode = 404;
    res.end('{}');
  });
  const client = makeClient(url);
  await assert.rejects(() => client.getDistTags(), /not found.*my-package/s);
});

test('500 responses are retried with backoff until success', async () => {
  let requests = 0;
  const { url } = await startMockRegistry((req, res) => {
    requests++;
    if (requests < 3) {
      res.statusCode = 500;
      res.end('boom');
    } else {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ latest: '1.0.0' }));
    }
  });
  const client = makeClient(url, { maxRetries: 3, baseDelayMs: 5 });
  const tags = await client.getDistTags();
  assert.deepEqual(tags, { latest: '1.0.0' });
  assert.equal(requests, 3);
});

test('500 responses beyond maxRetries surface a RegistryError', async () => {
  let requests = 0;
  const { url } = await startMockRegistry((req, res) => {
    requests++;
    res.statusCode = 502;
    res.end('bad gateway');
  });
  const client = makeClient(url, { maxRetries: 2, baseDelayMs: 5 });
  await assert.rejects(() => client.getDistTags(), (err) => {
    assert.ok(err instanceof RegistryError);
    assert.equal(err.status, 502);
    return true;
  });
  assert.equal(requests, 3, '1 initial + 2 retries');
});

test('slow registry hits the request timeout', async () => {
  let requests = 0;
  const { url } = await startMockRegistry((req, res) => {
    requests++;
    setTimeout(() => res.end('{}'), 500); // longer than client timeout
  });
  const client = makeClient(url, { timeoutMs: 50, maxRetries: 1, baseDelayMs: 5 });
  await assert.rejects(() => client.getDistTags(), /timed out/);
  assert.equal(requests, 2, 'timeouts are treated as retriable network errors');
});

test('writes are serialized so a process never races its own dist-tag updates', async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  const { url } = await startMockRegistry((req, res) => {
    inFlight++;
    maxInFlight = Math.max(maxInFlight, inFlight);
    setTimeout(() => {
      inFlight--;
      res.setHeader('content-type', 'application/json');
      res.end('{}');
    }, 20);
  });
  const client = makeClient(url);
  await Promise.all([
    client.setDistTag('x-a', '1.0.0'),
    client.setDistTag('x-b', '1.0.0'),
    client.deleteDistTag('x-c'),
    client.setDistTag('x-d', '1.0.0'),
  ]);
  assert.equal(maxInFlight, 1, 'overlapping writes silently clobber each other on real registries');
});

test('unreachable registry produces a network RegistryError', async () => {
  // closed port: start then stop a server to get a guaranteed-unused port
  const { server, url } = await startMockRegistry(() => {});
  await new Promise((r) => server.close(r));
  const client = makeClient(url, { maxRetries: 1, baseDelayMs: 5 });
  await assert.rejects(() => client.getDistTags(), (err) => {
    assert.ok(err instanceof RegistryError);
    assert.match(err.message, /network error/);
    return true;
  });
});
