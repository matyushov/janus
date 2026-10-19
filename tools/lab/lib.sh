#!/usr/bin/env bash
# Shared helpers of the janus lab scripts. Sourced, never run directly.

lab_die() { echo "error: $*" >&2; exit 1; }

# lab_need VAR [hint]: stop unless the environment variable VAR is set and not empty.
lab_need() {
  [ -n "${!1:-}" ] || lab_die "$1 is not set${2:+ ($2)}"
}

# Where the scripts keep their files on the machine they run on (guest or host).
LAB_DIR="${JANUS_LAB_DIR:-$HOME/j4}"

# sudo with an optional password from the environment. LAB VMs ONLY: the password
# travels through the environment, never put a real one here.
lab_sudo() {
  if [ -n "${JANUS_LAB_SUDO_PASSWORD:-}" ]; then
    printf '%s\n' "$JANUS_LAB_SUDO_PASSWORD" | sudo -S -p '' "$@"
  else
    sudo "$@"
  fi
}

# The port part of "host:port".
lab_port_of() { echo "${1##*:}"; }
