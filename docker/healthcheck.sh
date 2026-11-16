#!/bin/sh
# Живая проверка: настоящее Noise-соединение + Ping к своей же ноде через localhost.
set -eu
port="${CORE_LISTEN##*:}"
addr=$(core-node --public-host "127.0.0.1:${port}" info | sed -n 's/^address: //p')
exec core-cli ping --count 1 "$addr" >/dev/null
