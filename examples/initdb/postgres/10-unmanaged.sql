-- Objects that exist on the server but are not in examples/postgres/*.hcl,
-- so that the first plan has something to warn about.

-- Not declared: plan warns "unmanaged user", and --prune drops it.
CREATE ROLE stray_reporter LOGIN PASSWORD 'stray-password';

-- Not declared: plan warns "unmanaged database", and --prune drops it.
CREATE DATABASE legacy_reports;

-- Matched by the ignore block: neither reported nor pruned.
CREATE ROLE monitoring LOGIN PASSWORD 'monitoring-password';
