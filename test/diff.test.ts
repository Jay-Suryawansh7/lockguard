import { parseLockfile } from '../src/lib/parser.js';
import { computeDiff, pathToPackageName, isSuspiciousDiff, getRiskScore } from '../src/lib/diff.js';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLockfile as pl } from '../src/lib/parser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('diff', () => {
  const fixturePath = resolve(__dirname, '../fixtures/package-lock.json');
  const fixture = readFileSync(fixturePath, 'utf-8');
  const lockfile = parseLockfile(fixture);

  test('pathToPackageName extracts package name from node_modules path', () => {
    expect(pathToPackageName('node_modules/lodash')).toBe('lodash');
    expect(pathToPackageName('node_modules/@sentry/core')).toBe('core');
    expect(pathToPackageName('node_modules/foo')).toBe('foo');
    expect(pathToPackageName('something/else')).toBe(null);
  });

  test('computeDiff finds added packages', () => {
    const empty = parseLockfile('{"packages":{}}');
    const diff = computeDiff(lockfile, empty);
    expect(diff.totalAdded).toBeGreaterThan(0);
    expect(diff.added.some(a => a.name === 'axios')).toBe(true);
  });

  test('computeDiff finds removed packages', () => {
    const empty = parseLockfile('{"packages":{}}');
    const diff = computeDiff(empty, lockfile);
    expect(diff.totalRemoved).toBeGreaterThan(0);
    expect(diff.removed.some(r => r.name === 'axios')).toBe(true);
  });

  test('computeDiff finds changed packages', () => {
    const modified = JSON.parse(fixture);
    (modified.packages as Record<string, Record<string, unknown>>)['node_modules/lodash'] = {
      version: '4.18.0',
    };
    const modifiedLockfile = parseLockfile(JSON.stringify(modified));
    const diff = computeDiff(modifiedLockfile, lockfile);
    expect(diff.changed.some(c => c.name === 'lodash')).toBe(true);
  });

  test('isSuspiciousDiff detects suspicious package names', () => {
    const susp = pl(JSON.stringify({
      packages: {
        '': {},
        'node_modules/postinstall-js': { version: '1.0.0' },
      },
    }));
    const diff = computeDiff(susp, pl('{"packages":{}}'));
    expect(isSuspiciousDiff(diff)).toBe(true);
  });

  test('getRiskScore returns numeric score', () => {
    const diff = computeDiff(lockfile, parseLockfile('{"packages":{}}'));
    const score = getRiskScore(diff);
    expect(typeof score).toBe('number');
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });
});
