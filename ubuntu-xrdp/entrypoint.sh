#!/usr/bin/env bash

# Create the user account
if ! id aluno >/dev/null 2>&1; then
    groupadd --gid 1020 aluno
    useradd --shell /bin/bash --uid 1020 --gid 1020 --groups sudo --password "$(openssl passwd rnpesr)" --create-home --home-dir /home/aluno aluno
fi

# Remove existing sesman/xrdp PID files to prevent rdp sessions hanging on container restart
[ ! -f /var/run/xrdp/xrdp-sesman.pid ] || rm -f /var/run/xrdp/xrdp-sesman.pid
[ ! -f /var/run/xrdp/xrdp.pid ] || rm -f /var/run/xrdp/xrdp.pid

# Start xrdp sesman service
/usr/sbin/xrdp-sesman &

# Start SSH server in background
/usr/sbin/sshd &

# Run xrdp in foreground if no commands specified
if [ -z "$1" ]; then
    /usr/sbin/xrdp --nodaemon
else
    /usr/sbin/xrdp
    exec "$@"
fi
