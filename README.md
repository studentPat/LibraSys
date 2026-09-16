# LibraSys

Secure single-branch physical library management built with MySQL, ASP.NET 8 Web API, and vanilla HTML/CSS/JavaScript.

## Quick start

1. Run `database/migrations/001_initial_schema.sql` and `database/seeds/001_reference_data.sql` with a migration account.
2. Provision runtime/reporting accounts from `database/operations/security-and-operations.sql` using a secret manager.
3. Set `ConnectionStrings__LibraryDatabase` (including a real password and TLS certificate settings) and run `dotnet run --project src/LibraSys.Api`.
4. Serve `frontend` from a static web server and set `window.LIBRASYS_API` to the API origin if it is not the default.
5. Run `dotnet test LibraSys.slnx`.

See `docs/requirements.md` and `docs/security-operations.md` for business rules, least privilege, backup/PITR, restore testing, and query tuning guidance.
