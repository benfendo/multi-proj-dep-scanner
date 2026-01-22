#!/usr/bin/env node
const path = require('path');
const fs = require('fs');
const { Command } = require('commander');
// avoid ESM-only chalk in CommonJS CLI; use console for errors
const { runScan, runInventory, runCompare, runNearMiss } = require('../lib/scanner');

const program = new Command();

program
  .name('mpds')
  .description('Multi-project dependency scanner — check package-locks against an authoritative CSV')
  .option('-t, --target <path>', 'target directory to scan (or set SCAN_TARGET)', process.env.SCAN_TARGET || process.cwd())
  .option('-c, --csv <path>', 'authoritative CSV file (or set INPUT_CSV)', process.env.INPUT_CSV)
  .option('-o, --out <path>', 'output directory (defaults to cwd)', process.env.OUT_DIR || process.cwd())
  .option('-m, --mode <mode>', 'mode: scan|inventory|compare|near-miss', 'scan')
  .option('--inventory <path>', 'inventory CSV file (used by near-miss mode)', './output/inventory.csv')
  .option('--ignore <pattern>', 'glob ignore pattern (comma separated)', '')
  .parse(process.argv);

const opts = program.opts();

function fail(msg) {
  console.error('Error:', msg);
  process.exit(2);
}

if (!fs.existsSync(opts.target)) fail(`Target path not found: ${opts.target}`);
if (opts.mode === 'near-miss') {
  if (!opts.csv) fail('Missing --csv argument (or INPUT_CSV env var) pointing to the authoritative CSV');
  if (!fs.existsSync(opts.csv)) fail(`CSV file not found: ${opts.csv}`);
  if (!opts.inventory) fail('Missing --inventory argument pointing to an inventory CSV');
  if (!fs.existsSync(opts.inventory)) fail(`Inventory CSV not found: ${opts.inventory}`);
} else if (opts.mode !== 'inventory') {
  if (!opts.csv) fail('Missing --csv argument (or INPUT_CSV env var) pointing to the authoritative CSV');
  if (!fs.existsSync(opts.csv)) fail(`CSV file not found: ${opts.csv}`);
}

(async () => {
  try {
    if (opts.mode === 'inventory') {
      await runInventory({ target: opts.target, out: opts.out, ignore: opts.ignore });
    } else if (opts.mode === 'compare') {
      await runCompare({ target: opts.target, csv: opts.csv, out: opts.out, ignore: opts.ignore });
    } else if (opts.mode === 'near-miss') {
      await runNearMiss({ authCsv: opts.csv, inventoryCsv: opts.inventory, out: opts.out });
    } else {
      await runScan({ target: opts.target, csv: opts.csv, out: opts.out, ignore: opts.ignore });
    }
  } catch (err) {
    console.error('Fatal:', err && err.message ? err.message : String(err));
    process.exit(3);
  }
})();
