const assert = require('assert');
const semver = require('semver');
const path = require('path');
const { normalizeConstraint, normalizeVersion, buildCSVMap } = require('../lib/scanner');

console.log('Running version-format unit tests...');

// normalizeConstraint removes spaces after '=' and strips quotes
assert.strictEqual(normalizeConstraint('= 1.2.3'), '=1.2.3');
assert.strictEqual(normalizeConstraint('"= 2.0.0"'), '=2.0.0');

// normalizeVersion strips leading v
assert.strictEqual(normalizeVersion('v1.2.3'), '1.2.3');
assert.strictEqual(normalizeVersion('1.2.3'), '1.2.3');

// semver matching complex OR'ed exact equals
const constraintRaw = '= 2.23.2 || = 2.23.3 || = 2.23.4';
const c = normalizeConstraint(constraintRaw);
const good = ['2.23.2','2.23.3','2.23.4'];
for (const v of good) {
  const vclean = semver.coerce(v) ? semver.coerce(v).version : v;
  assert.ok(semver.satisfies(vclean, c, { includePrerelease: true }), `${v} should satisfy ${c}`);
}
assert.ok(!semver.satisfies('2.23.1', c));

// buildCSVMap should map different CSV-style rows; simulate rows
const rows = [
  { Package: 'foo', Version: '= 1.0.0', notes: 'n' },
  { packageName: 'bar', vulnerableConstraint: '^2.0.0' }
];
const m = buildCSVMap(rows);
assert.ok(m.foo && m.foo.length === 1 && m.foo[0].constraint === '=1.0.0');
assert.ok(m.bar && m.bar.length === 1 && m.bar[0].constraint === '^2.0.0');

console.log('All tests passed.');
