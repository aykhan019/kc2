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

test('application containers use pinned images and a non-root runtime', () => {
  const dockerfile = fs.readFileSync('docker/Dockerfile', 'utf8');
  const compose = fs.readFileSync('docker/docker-compose.yml', 'utf8');
  assert.match(dockerfile, /^FROM node:[^\n]+@sha256:[a-f0-9]{64}$/m);
  assert.match(dockerfile, /^USER node$/m);
  assert.match(compose, /verdaccio\/verdaccio:[^\s]+@sha256:[a-f0-9]{64}/);
});

test('application containers drop capabilities and persist private state', () => {
  const compose = fs.readFileSync('docker/docker-compose.yml', 'utf8');
  assert.match(compose, /cap_drop:\n\s+- ALL/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /NPM_C2_STATE_FILE: \/state\//);
  assert.match(compose, /read_only: true/);
});

test('local registry cannot proxy package requests to a public uplink', () => {
  const config = fs.readFileSync('docker/verdaccio.yaml', 'utf8');
  assert.doesNotMatch(config, /^uplinks:/m);
  assert.doesNotMatch(config, /^\s+proxy:/m);
});
