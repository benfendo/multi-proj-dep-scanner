#!/usr/bin/env node
const {execSync} = require('child_process');
const fs = require('fs');
const path = require('path');

const root = process.cwd();

function findPackageJsonDirs(dir) {
  const results = [];
  function walk(current) {
    const entries = fs.readdirSync(current, {withFileTypes: true});
    if (entries.some(e => e.name === 'package.json')) {
      results.push(current);
      // do not descend into this directory further
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === '.git' || e.name === 'dist' || e.name === 'build') continue;
        try {
          walk(path.join(current, e.name));
        } catch (err) {
          // ignore permission errors
        }
      }
    }
  }
  walk(dir);
  return results;
}

function runAudit(dir) {
  try {
    const out = execSync('npm audit --json', {cwd: dir, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024});
    return {ok:true, output: out};
  } catch (err) {
    // npm audit exits nonzero when vulnerabilities found; stdout may still contain JSON
    if (err.stdout) {
      return {ok:true, output: err.stdout};
    }
    return {ok:false, error: err.message};
  }
}

function runGitUpdate(dir) {
  try {
    // fetch and fast-forward pull where possible; ignore any errors (dirty worktrees, non-git dirs)
    execSync('git fetch --all && git pull --ff-only', {cwd: dir, stdio: 'ignore', timeout: 60 * 1000});
    return true;
  } catch (err) {
    return false;
  }
}

function getGitBranch(dir) {
  try {
    const b = execSync('git rev-parse --abbrev-ref HEAD', {cwd: dir, encoding: 'utf8', stdio: ['ignore','pipe','ignore']});
    return b.toString().trim();
  } catch (err) {
    return '';
  }
}

function extractCounts(auditJson) {
  try {
    const data = typeof auditJson === 'string' ? JSON.parse(auditJson) : auditJson;
    // Newer npm formats include metadata.vulnerabilities and metadata.total
    if (data.metadata && data.metadata.vulnerabilities) {
      const v = data.metadata.vulnerabilities;
      const total = data.metadata.total || Object.values(v).reduce((s,n)=>s+(n||0),0);
      return {
        total: total || 0,
        low: v.low || 0,
        moderate: v.moderate || 0,
        high: v.high || 0,
        critical: v.critical || 0,
      };
    }
    // Fallback: look for vulnerabilities object at top-level
    if (data.vulnerabilities) {
      const v = data.vulnerabilities;
      const low = Object.values(v).filter(x=>x.severity==='low').length;
      const moderate = Object.values(v).filter(x=>x.severity==='moderate').length;
      const high = Object.values(v).filter(x=>x.severity==='high').length;
      const critical = Object.values(v).filter(x=>x.severity==='critical').length;
      const total = low+moderate+high+critical;
      return {total, low, moderate, high, critical};
    }
    // As a last resort, return zeros
    return {total:0, low:0, moderate:0, high:0, critical:0};
  } catch (err) {
    return null;
  }
}

(async ()=>{
  console.log('Scanning for projects with package.json...');
  const dirs = findPackageJsonDirs(root);
  console.log(`Found ${dirs.length} project(s).`);

  const results = [];
  for (const d of dirs) {
    const repoName = path.basename(d);
    // try to update the repo to tip of default branch (ignore any errors)
    runGitUpdate(d);
    const branchName = getGitBranch(d);
    process.stdout.write(`Running npm audit in ${d} ... `);
    const res = runAudit(d);
    if (!res.ok) {
      console.log('ERROR');
      results.push({repo:repoName, total:'ERROR', low:'ERROR', moderate:'ERROR', high:'ERROR', critical:'ERROR', path: d});
      continue;
    }
    const counts = extractCounts(res.output);
    if (!counts) {
      console.log('PARSE_ERROR');
      results.push({repo:repoName, branch:branchName, total:'PARSE_ERROR', low:'PARSE_ERROR', moderate:'PARSE_ERROR', high:'PARSE_ERROR', critical:'PARSE_ERROR', path: d});
      continue;
    }
    console.log(`OK (total=${counts.total})`);
    results.push({repo:repoName, branch:branchName, total:counts.total, low:counts.low, moderate:counts.moderate, high:counts.high, critical:counts.critical, path: d});
  }

  const csvLines = [];
  csvLines.push('repo,branch,total,low,moderate,high,critical');
  for (const r of results) {
    csvLines.push(`${r.repo},${r.branch || ''},${r.total},${r.low},${r.moderate},${r.high},${r.critical}`);
  }
  const outPath = path.join(root, 'audit-results.csv');
  fs.writeFileSync(outPath, csvLines.join('\n'), 'utf8');
  console.log('\nWrote CSV to', outPath);
  console.log('Summary (first 40 rows):');
  console.log(csvLines.slice(0,41).join('\n'));
})();
