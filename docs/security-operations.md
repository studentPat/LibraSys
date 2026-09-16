# Security and operations

Use separate `librasys_runtime`, `librasys_reporting`, `librasys_migrator`, and DBA accounts from `database/operations/security-and-operations.sql`. Replace placeholder passwords using a secret manager; never commit them. Runtime connections must use TLS certificate verification and a private network. Rotate credentials and revoke sessions after suspected compromise.

Enable structured application audit events and immutable `audit_logs` records for authentication, catalog/member changes, circulation, fines, and payments. Encrypt backups and sensitive exports with managed keys; document key ownership, rotation, and break-glass access. Do not store raw passwords or payment card data.

Run full backups daily, binlog shipping continuously, and verify restore to an isolated MySQL instance at least quarterly. Target RPO 15 minutes and RTO 4 hours unless the deployment owner approves otherwise. Retain backups according to policy and test logical and physical restore procedures.

For tuning, run `EXPLAIN ANALYZE` on catalog search, member history, overdue report, and reservation queue queries. Preserve composite indexes, use bounded page sizes, and prefer keyset pagination for large deployments.

For split frontend/API deployments, set `Cors:AllowedOrigins` to the exact HTTPS frontend origins. Keep production origins in deployment configuration, never use `*` for authenticated traffic, and do not enable credential sharing unless the deployment explicitly requires it.
