#!/usr/bin/env bash
# set-activation-policy.sh INSTANCE POLICY starts (ALWAYS) or stops (NEVER)
# a Cloud SQL instance and waits until it is done.
#
# A patch fails with 409 while another operation runs (such as the stop of
# the previous run), so pending operations are waited for first. Starting a
# stopped instance may take longer than gcloud waits by default, so the
# operation is waited for without a limit: the job's timeout bounds it.
set -euo pipefail

instance=${1:?instance}
policy=${2:?policy}

for op in $(gcloud sql operations list --instance "$instance" --filter 'status!=DONE' --format 'value(name)'); do
  echo "waiting for pending operation $op"
  gcloud sql operations wait "$op" --timeout unlimited
done

op=$(gcloud sql instances patch "$instance" --activation-policy "$policy" --async --quiet --format 'value(name)')
echo "waiting for $policy ($op)"
gcloud sql operations wait "$op" --timeout unlimited
