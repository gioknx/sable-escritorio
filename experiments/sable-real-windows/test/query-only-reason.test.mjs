import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { QueryFailure, publicReason } from '../ci/query-only.mjs';

const secrets = ['!private-room', '$private-event', '@private-user:escritorio.localhost', 'private-query-canary-0123456789abcdef'];

test('query-only failure reasons are fixed codes: no compared identifier, message or canary reaches the public report', () => {
  const leaking = [
    (() => { try { assert.deepEqual(['!changed', secrets[1], secrets[2]], secrets.slice(0, 3)); } catch (e) { return e; } })(),
    (() => { try { assert.equal('altered', secrets[3]); } catch (e) { return e; } })(),
    Object.assign(new Error(`HTTP 400 ${secrets.join(' ')}`), { code: 'ERR_' + secrets[0] }),
    new QueryFailure('present-event-rejected'),
  ];
  for (const error of leaking) {
    const reason = publicReason(error);
    for (const secret of secrets) assert.equal(reason.includes(secret), false, `${reason} leaks`);
    assert.match(reason, /^[A-Za-z0-9:_.-]{1,64}$/);
  }
  assert.equal(publicReason(new QueryFailure('present-event-rejected')), 'present-event-rejected');
});

test('query-only source never publishes a raw error message nor uses value-printing assertions', () => {
  const source = readFileSync(new URL('../ci/query-only.mjs', import.meta.url), 'utf8');
  assert.equal(/error\.message/.test(source), false);
  assert.equal(/\bassert\./.test(source), false);
  assert.equal(/report\.status = 'QUERY_CHECKED'/.test(source), true);
  assert.equal(/nativeAuthorization: false/.test(source), true);
  assert.equal(/nativeAuthorization: true|PASS/.test(source), false);
});
