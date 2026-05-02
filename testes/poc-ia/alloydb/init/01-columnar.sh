#!/bin/bash
set -e

echo "google_columnar_engine.enabled = 'on'" >> "$PGDATA/postgresql.conf"
echo "google_columnar_engine.memory_size_in_mb = '1024'" >> "$PGDATA/postgresql.conf"
echo "google_columnar_engine.enable_vectorized_join = 'on'" >> "$PGDATA/postgresql.conf"
