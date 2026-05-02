#!/bin/bash
set -e

echo "host all all 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
echo "listen_addresses='*'" >> "$PGDATA/postgresql.conf"