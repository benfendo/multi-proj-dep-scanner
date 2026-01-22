const assert = require('assert');
const { isConstraintValid } = require('../lib/scanner');

const cases = [
  ['~1.2.3', true],
  ['>1.2.0', true],
  ['^2.0.0', true],
  ['1.2.x', true],
  ['1.2.3-beta.1', true],
  ['*', true],
  ['not-a-range', false],
  ['', false],
  ['= 1.3.3', true]
];

for (const [input, expected] of cases) {
  const got = isConstraintValid(input);
  assert.strictEqual(got, expected, `isConstraintValid('${input}') -> ${got}, expected ${expected}`);
}

console.log('Constraint validator tests passed.');
