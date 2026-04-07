import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLockfile, buildDependencyTree, flattenTree, getAllPackages } from '../src/lib/parser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

describe('parser', () => {
  const fixturePath = resolve(__dirname, '../fixtures/package-lock.json');
  const fixture = readFileSync(fixturePath, 'utf-8');

  test('parses lockfile JSON', () => {
    const result = parseLockfile(fixture);
    expect(result.name).toBe('test-project');
    expect(result.version).toBe('1.0.0');
  });

  test('extracts all packages from packages section', () => {
    const result = parseLockfile(fixture);
    const pkgs = getAllPackages(result);
    expect(pkgs.length).toBeGreaterThan(0);
    expect(pkgs.some(p => p.path === 'node_modules/axios')).toBe(true);
    expect(pkgs.some(p => p.path === 'node_modules/lodash')).toBe(true);
  });

  test('identifies scoped packages', () => {
    const result = parseLockfile(fixture);
    const pkgs = getAllPackages(result);
    expect(pkgs.some(p => p.path === 'node_modules/@sentry/core')).toBe(true);
  });

  test('buildDependencyTree creates a tree from lockfile', () => {
    const lockfile = parseLockfile(fixture);
    const tree = buildDependencyTree(lockfile, 'test-project', '1.0.0');
    expect(tree.name).toBe('test-project');
    expect(tree.version).toBe('1.0.0');
    expect(tree.children.length).toBeGreaterThan(0);
  });

  test('flattenTree returns all nodes', () => {
    const lockfile = parseLockfile(fixture);
    const tree = buildDependencyTree(lockfile, 'test-project', '1.0.0');
    const flat = flattenTree(tree);
    expect(flat.length).toBeGreaterThanOrEqual(1);
  });

  test('handles malformed JSON gracefully', () => {
    expect(() => parseLockfile('not json')).toThrow();
  });
});
