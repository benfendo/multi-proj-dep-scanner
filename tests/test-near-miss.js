const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { runNearMiss } = require('../lib/scanner');

// Create a temporary workspace for the test
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mpds-test-'));
const out = path.join(tmp, 'out');
fs.mkdirSync(out);

const authCsv = path.join(tmp, 'auth.csv');
const inventoryCsv = path.join(tmp, 'inventory.csv');

// authoritative CSV: package foo requires >=1.2.0, bar requires =2.0.0
fs.writeFileSync(authCsv, 'Package,Version\nfoo,>=1.2.0\nbar,= 2.0.0\n');

// inventory CSV: foo at 1.1.0 (near-miss), foo at 1.2.3 (satisfies), bar at 2.0.1 (near-miss), baz not in auth
fs.writeFileSync(inventoryCsv, 'packageName,version,lockfilePath\nfoo,1.1.0,/some/path/a\nfoo,1.2.3,/some/path/b\nbar,2.0.1,/some/path/c\nbaz,0.1.0,/some/path/d\n');

(async () => {
  await runNearMiss({ authCsv, inventoryCsv, out });
  const outPath = path.join(out, 'near-miss.csv');
  assert.ok(fs.existsSync(outPath), 'near-miss.csv should be created');
  const content = fs.readFileSync(outPath, 'utf8');
  // Expect rows for foo@1.1.0 and bar@2.0.1
  assert.ok(content.includes('foo'), 'output should include foo');
  assert.ok(content.includes('/some/path/a'), 'output should include lockfile path for foo 1.1.0');
  assert.ok(content.includes('bar'), 'output should include bar');
  // Should not include foo@1.2.3 because it satisfies constraint
  assert.ok(!content.includes('/some/path/b'), 'satisfying version should not be included');
  console.log('Near-miss test passed.');
})();
