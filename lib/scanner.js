const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse/sync');
const glob = require('glob');
const semver = require('semver');

function maybeRelativeToCwd(p) {
  try {
    const abs = path.resolve(p);
    const cwd = process.cwd();
    const rel = path.relative(cwd, abs);
    if (!rel) return '.';
    // if relative path does not escape the cwd, return it
    if (!rel.startsWith('..') && !path.isAbsolute(rel)) return rel;
    return abs;
  } catch (e) {
    return p;
  }
}

function isConstraintValid(rawConstraint) {
  const c = normalizeConstraint(rawConstraint);
  if (!c) return false;
  try {
    // semver.validRange returns null for unparsable ranges
    const vr = semver.validRange(c);
    return vr !== null;
  } catch (e) {
    return false;
  }
}

function validateCSVRows(rows) {
  const invalid = [];
  for (const r of rows) {
    const name = ((r.packageName || r.package || r.name || r.Package || r.PACKAGE) || '').trim();
    const rawConstraint = (r.vulnerableConstraint || r.constraint || r.range || r.Version || r.version || r.VersionRange || r.VersionConstraint || '').trim();
    if (!rawConstraint) continue;
    if (!isConstraintValid(rawConstraint)) {
      invalid.push({ name, rawConstraint, rawRow: r });
    }
  }
  return invalid;
}

function readCsv(csvPath) {
  const src = fs.readFileSync(csvPath, 'utf8');
  const rows = parse(src, { columns: true, skip_empty_lines: true });
  return rows;
}

function normalizeConstraint(raw) {
  if (!raw) return '';
  let s = String(raw).trim();
  s = s.replace(/=\s*/g, '=');
  s = s.replace(/^"|"$/g, '');
  return s;
}

function buildCSVMap(rows) {
  const map = {};
  for (const r of rows) {
    const name = ((r.packageName || r.package || r.name || r.Package || r.PACKAGE) || '').trim();
    const rawConstraint = (r.vulnerableConstraint || r.constraint || r.range || r.Version || r.version || r.VersionRange || r.VersionConstraint || '').trim();
    const constraint = normalizeConstraint(rawConstraint);
    const notes = (r.notes || r.note || r.description || '').trim();
    if (!name) continue;
    if (!map[name]) map[name] = [];
    map[name].push({ constraint, notes, raw: r });
  }
  return map;
}

function extractFromLockV2(lockJson) {
  const pkgs = {};
  if (!lockJson.packages) return pkgs;
  for (const key of Object.keys(lockJson.packages)) {
    const entry = lockJson.packages[key];
    let name = null;
    if (key === '') name = entry.name || null;
    else if (key.startsWith('node_modules/')) name = key.replace(/^node_modules\//, '');
    else name = entry.name || null;
    if (!name) continue;
    const version = entry.version || null;
    if (!version) continue;
    if (!pkgs[name]) pkgs[name] = new Set();
    pkgs[name].add(version);
  }
  const out = {};
  for (const k of Object.keys(pkgs)) out[k] = Array.from(pkgs[k]);
  return out;
}

function extractFromLockV1(lockJson) {
  const pkgs = {};
  function walkDeps(depMap) {
    if (!depMap) return;
    for (const [name, meta] of Object.entries(depMap)) {
      if (meta && meta.version) {
        if (!pkgs[name]) pkgs[name] = new Set();
        pkgs[name].add(meta.version);
      }
      if (meta && meta.dependencies) walkDeps(meta.dependencies);
    }
  }
  walkDeps(lockJson.dependencies);
  const out = {};
  for (const k of Object.keys(pkgs)) out[k] = Array.from(pkgs[k]);
  return out;
}

function normalizeVersion(v) {
  if (!v) return v;
  return v.startsWith('v') ? v.slice(1) : v;
}

async function runScan({ target, csv, out, ignore }) {
  const rows = readCsv(csv);
  const invalidConstraints = validateCSVRows(rows);
  if (invalidConstraints.length) {
    console.warn(`Warning: ${invalidConstraints.length} unparsable constraint(s) found in authoritative CSV:`);
    for (const ic of invalidConstraints) {
      console.warn(` - ${ic.name || '<unknown>'}: ${ic.rawConstraint}`);
    }
  }
  const csvMap = buildCSVMap(rows);
  const lockPaths = glob.sync('**/package-lock.json', { cwd: target, absolute: true, ignore: (ignore||'').split(',').map(s=>s.trim()).filter(Boolean).concat(['**/node_modules/**','**/dist/**']) });

  const hits = [];
  for (const lockfilePath0 of lockPaths) {
  const lockfilePath = maybeRelativeToCwd(lockfilePath0);
    let json;
  try { json = JSON.parse(fs.readFileSync(lockfilePath0, 'utf8')); } catch (e) { continue; }
    const lockVersion = json.lockfileVersion || 1;
    const pkgMap = lockVersion >= 2 ? extractFromLockV2(json) : extractFromLockV1(json);
    for (const [pkgName, versions] of Object.entries(pkgMap)) {
      const constraints = csvMap[pkgName] || [];
      if (!constraints.length) continue;
      for (const ver of versions) {
        const norm = normalizeVersion(ver);
        const coerce = semver.coerce(norm);
        const vclean = coerce ? coerce.version : norm;
        for (const c of constraints) {
          const range = c.constraint;
          if (!range) continue;
          let matched = false;
          try { matched = semver.satisfies(vclean, range, { includePrerelease: true }); } catch (e) { matched = (norm === range || norm === range.replace(/^v/, '')); }
          if (matched) {
            hits.push({ lockfilePath, packageName: pkgName, resolvedVersion: ver, vulnerableConstraint: range, notes: c.notes || '' });
          }
        }
      }
    }
  }

  const outJson = { scannedAt: new Date().toISOString(), target, csv, totalLockfiles: lockPaths.length, hitsCount: hits.length, unparsableConstraints: invalidConstraints };
  if (!fs.existsSync(out)) fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(outJson, null, 2));
  const header = 'lockfilePath,packageName,resolvedVersion,vulnerableConstraint,notes\n';
  const lines = hits.map(h => [h.lockfilePath, h.packageName, h.resolvedVersion, '"' + (h.vulnerableConstraint || '') + '"', '"' + (h.notes || '') + '"'].join(','));
  fs.writeFileSync(path.join(out, 'report.csv'), header + lines.join('\n'));
  console.log('Scan complete. lockfiles:', lockPaths.length, 'hits:', hits.length);
  console.log('Wrote report.json and report.csv to', out);
}

async function runInventory({ target, out, ignore }) {
  const lockPaths = glob.sync('**/package-lock.json', { cwd: target, absolute: true, ignore: (ignore||'').split(',').map(s=>s.trim()).filter(Boolean).concat(['**/node_modules/**','**/dist/**']) });
  const outLines = [];
  const unique = new Map();
  for (const lockfilePath0 of lockPaths) {
    const lockfilePath = maybeRelativeToCwd(lockfilePath0);
    let json; try { json = JSON.parse(fs.readFileSync(lockfilePath0, 'utf8')); } catch (e) { continue; }
    const lockVersion = json.lockfileVersion || 1;
    const pkgs = lockVersion >= 2 ? extractFromLockV2(json) : extractFromLockV1(json);
    for (const [name, versions] of Object.entries(pkgs)) {
      for (const v of versions) {
        outLines.push([name, v, lockfilePath].join(','));
        unique.set(`${name}@@${v}`, true);
      }
    }
  }
  if (!fs.existsSync(out)) fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'inventory.csv'), 'packageName,version,lockfilePath\n' + outLines.join('\n'));
  fs.writeFileSync(path.join(out, 'unique-packages.txt'), Array.from(new Set(outLines.map(l=>l.split(',')[0]))).join('\n'));
  console.log('Inventory written to', out, 'unique packages:', new Set(outLines.map(l=>l.split(',')[0])).size);
}

async function runCompare({ target, csv, out, ignore }) {
  const uniquePath = path.join(out, 'unique-packages.txt');
  if (!fs.existsSync(uniquePath)) {
    throw new Error(`Unique packages list not found at ${uniquePath} — run inventory mode first`);
  }
  const authRows = readCsv(csv).map(r => (r.Package || r.package || r.PackageName || r.packageName || Object.values(r)[0] || '').trim()).filter(Boolean);
  const unique = new Set(fs.readFileSync(uniquePath, 'utf8').split(/\r?\n/).map(s=>s.trim()).filter(Boolean));
  const intersection = authRows.filter(p => unique.has(p));
  if (!fs.existsSync(out)) fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'intersection.txt'), intersection.join('\n'));
  fs.writeFileSync(path.join(out, 'intersection-count.txt'), String(intersection.length));
  console.log('Compare complete. intersection:', intersection.length);
}

async function runNearMiss({ authCsv, inventoryCsv, out }) {
  if (!authCsv || !inventoryCsv) throw new Error('authCsv and inventoryCsv required');
  const authRows = readCsv(authCsv);
  const authMap = new Map();
  for (const r of authRows) {
    const name = (r.Package || r.package || r.packageName || Object.values(r)[0] || '').trim();
    const rawConstraint = (r.Version || r.vulnerableConstraint || r.constraint || r.range || r.version || '').trim();
    if (!name) continue;
    authMap.set(name, normalizeConstraint(rawConstraint));
  }

  const inventoryRows = readCsv(inventoryCsv);
  const nearMisses = [];
  for (const row of inventoryRows) {
    const name = (row.packageName || row.Package || row.package || Object.values(row)[0] || '').trim();
    const version = (row.version || row.Version || row.resolvedVersion || Object.values(row)[1] || '').trim();
    const lockfilePath = (row.lockfilePath || row.lockfile || Object.values(row)[2] || '').trim();
    if (!authMap.has(name)) continue;
    const constraint = authMap.get(name);
    if (!constraint) continue;
    const vnorm = semver.coerce(version) ? semver.coerce(version).version : version;
    let satisfies = false;
    try { satisfies = semver.satisfies(vnorm, constraint, { includePrerelease: true }); } catch (e) { satisfies = (version === constraint || version === constraint.replace(/^v/, '')); }
    if (!satisfies) {
      nearMisses.push({ packageName: name, requiredConstraint: constraint, resolvedVersion: version, lockfilePath });
    }
  }

  if (!fs.existsSync(out)) fs.mkdirSync(out, { recursive: true });
  const outPath = path.join(out, 'near-miss.csv');
  const header = 'packageName,requiredConstraint,resolvedVersion,lockfilePath\n';
  const lines = nearMisses.map(m => [m.packageName, '"' + m.requiredConstraint + '"', m.resolvedVersion, m.lockfilePath].join(','));
  fs.writeFileSync(outPath, header + lines.join('\n'));
  console.log('Wrote', outPath, 'rows:', nearMisses.length);
}

module.exports = { runScan, runInventory, runCompare, runNearMiss, normalizeConstraint, normalizeVersion, buildCSVMap, isConstraintValid, validateCSVRows };
