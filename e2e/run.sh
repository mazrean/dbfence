#!/usr/bin/env bash
# Runs the dbfence end-to-end scenario against one server.
#
# DBFENCE_E2E_TARGET selects targets/<platform>-<engine> (aws-postgres,
# gcp-mysql, local-postgres, ...). Every phase is a directory of *.hcl files
# composed from scenario/<engine> and the target, and every apply is followed
# by `plan --detailed-exitcode`, which must report no changes. Only objects
# named e2e_* are created and pruned (see scenario/<engine>/ignore.hcl).
#
# Environment (see docs/e2e.md for what the cloud targets set):
#   DBFENCE_E2E_TARGET           required
#   DBFENCE_E2E_HOST             required; DBFENCE_E2E_PORT optional
#   DBFENCE_E2E_ADMIN_USER       required
#   DBFENCE_E2E_ADMIN_SECRET     aws/gcp: the secret holding the admin password
#   DBFENCE_E2E_ADMIN_PASSWORD   local: the admin password
#   DBFENCE_E2E_IAM_USER         gcp: the Cloud SQL IAM user of the job
#   DBFENCE_E2E_CONNECT_ATTEMPTS attempts of the first connection (default 6)
#   DBFENCE_E2E_CONNECT_TIMEOUT  seconds per connection (default 30)
#   DBFENCE                      the dbfence binary (default: dbfence in PATH)
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=${DBFENCE_E2E_TARGET:?DBFENCE_E2E_TARGET is required}
engine=${target#*-}
dbfence=${DBFENCE:-dbfence}
targetdir=$root/targets/$target
scenario=$root/scenario/$engine
[[ -d $targetdir && -d $scenario ]] || {
  echo "unknown target $target" >&2
  exit 2
}

log() { printf '\n==> %s\n' "$*"; }
fail() {
  printf '\nFAIL: %s\n' "$*" >&2
  exit 1
}

# Passwords of the users the scenario creates. They are new on every run,
# and dbfence redacts them in its output.
password() {
  local pw
  pw=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  # Upper case, lower case, digit and symbol, for password policies.
  printf 'Aa1-%s' "${pw:0:24}"
}
export DBFENCE_E2E_APP_PASSWORD=${DBFENCE_E2E_APP_PASSWORD:-$(password)}
export DBFENCE_E2E_APP_PASSWORD_NEXT=${DBFENCE_E2E_APP_PASSWORD_NEXT:-$(password)}
export DBFENCE_E2E_MIGRATOR_PASSWORD=${DBFENCE_E2E_MIGRATOR_PASSWORD:-$(password)}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# phase NAME FILE... copies the files into a new configuration directory.
phase() {
  local dir=$work/$1
  shift
  mkdir -p "$dir"
  local f
  for f in "$@"; do
    if [[ -f $f ]]; then
      cp "$f" "$dir/"
    fi
  done
  echo "$dir"
}

# Files that only some targets have are skipped by phase.
cleanup=$(phase cleanup "$scenario/ignore.hcl" "$targetdir/admin.hcl" "$targetdir/cleanup.hcl")
stage1=$(phase stage1 "$scenario/ignore.hcl" "$targetdir/admin.hcl" "$targetdir/iam_user.hcl" "$scenario"/stage1/*.hcl)
stage2=$(phase stage2 "$scenario/ignore.hcl" "$targetdir/admin.hcl" "$targetdir/iam_user.hcl" "$scenario"/stage2/*.hcl)
login=$(phase login "$targetdir/login.hcl")
iam=
if [[ -f $targetdir/iam.hcl ]]; then
  iam=$(phase iam "$targetdir/iam.hcl")
fi

# The warnings that the admin phases may print, without comments.
expected=$work/expected-warnings
grep -Ev '^(#|$)' "$scenario/expected-warnings" >"$expected" || true

# run_dbfence DIR ARG... runs dbfence on DIR and prints its output. In the admin
# phases (all but login and iam) a warning that expected-warnings does not
# list fails the run: dbfence warns about what it does not change.
run_dbfence() {
  local dir=$1 out=$work/output rc=0
  shift
  "$dbfence" -C "$dir" "$@" >"$out" 2>&1 || rc=$?
  cat "$out"
  if [[ $dir != "$login" && $dir != "$iam" ]]; then
    local unexpected
    unexpected=$(grep '^warning: ' "$out" | grep -Ev -f "$expected" | sort -u || true)
    [[ -z $unexpected ]] || fail "$(basename "$dir"): unexpected warnings:"$'\n'"$unexpected"
  fi
  return "$rc"
}

# converged DIR [FLAG...] runs plan, which must succeed without changes.
converged() {
  local dir=$1 rc=0
  shift
  log "plan -C $(basename "$dir") $* (must report no changes)"
  run_dbfence "$dir" plan --detailed-exitcode "$@" || rc=$?
  case $rc in
  0) ;;
  2) fail "$(basename "$dir"): plan still has changes after apply" ;;
  *) fail "$(basename "$dir"): plan failed with exit code $rc" ;;
  esac
}

apply() {
  local dir=$1
  shift
  log "apply -C $(basename "$dir") $*"
  run_dbfence "$dir" apply --auto-approve "$@" || fail "$(basename "$dir"): apply failed"
}

"$dbfence" --version

log "validate"
for dir in "$cleanup" "$stage1" "$stage2" "$login" ${iam:+"$iam"}; do
  "$dbfence" -C "$dir" validate || fail "$(basename "$dir"): invalid configuration"
done

# The first connection may wake a paused server (Aurora Serverless v2 with
# a minimum of 0 ACU takes some seconds to resume), so it is retried.
attempts=${DBFENCE_E2E_CONNECT_ATTEMPTS:-6}
for ((i = 1; ; i++)); do
  log "connect (attempt $i of $attempts)"
  if "$dbfence" -C "$cleanup" plan --prune; then
    break
  fi
  ((i < attempts)) || fail "cannot connect to the server"
  sleep 20
done

# Leftovers of an aborted run.
apply "$cleanup" --prune
converged "$cleanup" --prune

finished=
trap '[[ -n $finished ]] || { echo "cleaning up after the failure" >&2; "$dbfence" -C "$cleanup" apply --auto-approve --prune || true; }; rm -rf "$work"' EXIT

apply "$stage1" --target user.e2e_app
apply "$stage1"
converged "$stage1"

apply "$stage2" --prune --force-password
converged "$stage2" --prune

converged "$login"
if [[ -n $iam ]]; then
  converged "$iam"
fi

apply "$cleanup" --prune
converged "$cleanup" --prune
finished=1

log "PASS: $target"
