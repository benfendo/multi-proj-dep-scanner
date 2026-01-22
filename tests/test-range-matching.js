const assert = require('assert');
const semver = require('semver');
const { normalizeVersion } = require('../lib/scanner');

// Use the same normalization / matching approach as the scanner CLI
function scannerSatisfies(resolvedRaw, range) {
  const norm = normalizeVersion(resolvedRaw);
  const coerce = semver.coerce(norm);
  const vclean = coerce ? coerce.version : norm;
  try {
    return semver.satisfies(vclean, range, { includePrerelease: true }) || semver.satisfies(norm, range, { includePrerelease: true });
  } catch (e) {
    return false;
  }
}

const cases = [
  ['~1.0.4', '1.7.29', false],
  ['~1', '1.7.29', true],
  ['^1.0.4', '1.7.29', true],
  ['~1.0.4', '1.0.5', true],
  ['~1.0.4', '1.1.0', false],
  ['>1.2.0', '1.7.29', true],
  ['1.2.x', '1.2.3', true],
  ['1.2.x', '1.3.0', false],
  ['1.2.3-beta.1', '1.2.3-beta.1', true],
  ['*', '5.6.7', true]
];

for (const [range, resolved, expected] of cases) {
  const got = scannerSatisfies(resolved, range);
  assert.strictEqual(got, expected, `satisfies(${resolved}, ${range}) -> ${got}, expected ${expected}`);
}

console.log('Range matching tests passed.');
