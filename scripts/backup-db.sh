#!/usr/bin/env bash
set -euo pipefail
DB_PATH="${1:-/var/lib/kernel-cve-radar/kernel_cve.db}"
BACKUP_DIR="${2:-/var/backups/kernel-cve-radar}"
mkdir -p "$BACKUP_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="$BACKUP_DIR/kernel_cve-$STAMP.db"
python3 - "$DB_PATH" "$BACKUP" <<'PY'
import sqlite3, sys
src, dst = sys.argv[1:]
with sqlite3.connect(src) as source, sqlite3.connect(dst) as target:
    source.backup(target)
print(dst)
PY
find "$BACKUP_DIR" -type f -name 'kernel_cve-*.db' -mtime +30 -delete
