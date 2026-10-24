-- An admin like the master user of RDS or the postgres user of Cloud SQL:
-- it may create roles and databases, but is not a superuser.
CREATE ROLE dbfence_admin LOGIN CREATEROLE CREATEDB PASSWORD 'dbfence-admin';
