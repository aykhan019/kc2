import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('Docker lab binds the registry to loopback only', () => {
  const compose = fs.readFileSync('docker/docker-compose.yml', 'utf8');
  assert.match(compose, /127\.0\.0\.1:4873:4873/);
  assert.doesNotMatch(compose, /- ["']4873:4873["']/);
});

test('Docker lab does not use a known default registry password', () => {
  const setup = fs.readFileSync('docker/setup-registry.sh', 'utf8');
  assert.doesNotMatch(setup, /lab-password-123/);
  assert.match(setup, /randomBytes/);
});
