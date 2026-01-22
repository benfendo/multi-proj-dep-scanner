# Multi-Project Dependency Scanner (mpds)

Scan multiple projects for `package-lock.json` files and match package versions against an authoritative CSV of vulnerable packages / ranges.

## Usage

Install dependencies:

```sh
npm ci
```

Run tests:

```sh
npm run test
```

Run full scan (default mode):

```sh
npm run scan -- \
--target ~/bitbucket/okendo \
--csv ./input/shai-hulud-2-packages.csv
```

Run inventory (collect all packages & versions found):

```sh
npm run inventory -- \
--target ~/bitbucket/okendo
```

Look for near-misses (matching package but not version; must be run after `inventory`):

```sh
npm run near-miss -- \
--csv ./input/shai-hulud-2-packages.csv
```

Compare authoritative CSV against inventory uniques (must be run after `inventory`):

```sh
npm run compare -- \
--target ~/bitbucket/okendo \
--csv ./input/shai-hulud-2-packages.csv
```

## Example projects

Example project directories are included in `examples/projects`, and an input CSV at `input/example.csv`.

Commands:

```sh
# run a standard scan
npx scan --target ./examples/projects --csv ./input/example.csv --out ./examples/output

# run inventory over the example projects
npx scan --mode inventory --target ./examples/projects --out ./examples/output

# scan for near misses
npx scan --mode near-miss --csv ./input/example.csv --inventory ./examples/output/inventory.csv --out ./examples/output

# run a comparison
npx scan --mode compare --target ./examples/projects --csv ./input/example.csv --out ./examples/output
```

Expected matches for the provided examples:

- `project-alpha` (lockfile v1)
	- `@example/cli@2.2.7` — matches `= 2.2.7 || = 2.2.6`
	- `my-lib@0.9.1` — matches `~0.9.0`
- `project-beta` (lockfile v2)
	- `@example/csv-parse@4.0.5` — matches `= 4.0.5`
- `project-gamma` (lockfile v2, nested)
	- `my-builder@1.2.2` — matches `^1.2.1` (nested under `node_modules/foo/node_modules`)

Packages present but not matching the version constraints (near misses):

- `some-package@2.9.0` in `project-alpha` — does NOT satisfy `>=3.1.0 <4.0.0`
- `my-builder@1.1.0` in `project-beta` — does NOT satisfy `^1.2.1`

## Notes

- The CSV should have a column for package name (`Package`, `package`, `packageName`, etc.) and a column for version/range (`Version`, `vulnerableConstraint`, `constraint`, `range`, etc.).
- The app writes outputs into the `--out` directory (report.json, report.csv, inventory.csv, unique-packages.txt, intersection.txt).
- When a discovered lockfile is inside the current working directory, its path in generated reports will be written relative to the CWD (so example output in `examples/output` won't contain absolute, personal paths).
