#!/usr/bin/env node
/**
 * Structural backup of the project into backups/<timestamp>/.
 *
 * Copies source, config and docs (never node_modules or .git) and writes a
 * manifest with file count, total bytes and a SHA-256 checksum per file so a
 * restore can be verified. Intended to run before risky changes or on a cron.
 *
 * Usage:  node scripts/backup.js [--out DIR] [--keep N]
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.join(__dirname, '..');
const DEFAULT_OUT = path.join(ROOT, 'backups');
const EXCLUDED_DIRS = new Set(['node_modules', '.git', '.vercel', 'backups', 'coverage', '.cache']);
const EXCLUDED_FILES = new Set(['.DS_Store', 'Thumbs.db']);

function parseArgs(argv) {
  const args = { out: DEFAULT_OUT, keep: 5 };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out' && argv[i + 1]) args.out = path.resolve(argv[++i]);
    else if (argv[i] === '--keep' && argv[i + 1]) args.keep = Math.max(1, Number(argv[++i]) || 5);
  }
  return args;
}

function walk(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name), files);
    } else if (entry.isFile()) {
      if (EXCLUDED_FILES.has(entry.name)) continue;
      files.push(path.join(dir, entry.name));
    }
  }
  return files;
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function main() {
  const { out, keep } = parseArgs(process.argv.slice(2));
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const target = path.join(out, stamp);

  const files = walk(ROOT).filter(file => !file.startsWith(out + path.sep));
  fs.mkdirSync(target, { recursive: true });

  const manifest = { createdAt: new Date().toISOString(), root: ROOT, files: [], totalBytes: 0 };

  for (const file of files) {
    const relative = path.relative(ROOT, file);
    const destination = path.join(target, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(file, destination);

    const size = fs.statSync(file).size;
    manifest.totalBytes += size;
    manifest.files.push({
      path: relative.replace(/\\/g, '/'),
      bytes: size,
      sha256: sha256(file)
    });
  }

  fs.writeFileSync(path.join(target, 'backup-manifest.json'), JSON.stringify(manifest, null, 2));

  const existing = fs
    .readdirSync(out, { withFileTypes: true })
    .filter(e => e.isDirectory())
    .map(e => e.name)
    .sort();

  while (existing.length > keep) {
    const oldest = existing.shift();
    fs.rmSync(path.join(out, oldest), { recursive: true, force: true });
    console.log(`Pruned old backup: ${oldest}`);
  }

  console.log(`Backup complete: ${target}`);
  console.log(`Files: ${manifest.files.length} | Bytes: ${manifest.totalBytes}`);
}

main();
