# LibraSys requirements and business rules

LibraSys is a single-branch physical library system. A copy can have only one active borrowing; borrowing and return lock the copy row and commit as one transaction. Members must be active to borrow or reserve. Duplicate requests are prevented with idempotency keys. Reservations are queued FIFO per book and expire when their hold window ends. Fines are monetary records tied to a member and may only be paid up to the outstanding balance. Librarian and administrator operations require authenticated roles; member self-service is limited to that member's records.

Passwords use slow, salted PBKDF2 hashes and are never reversibly encrypted. API credentials come from a secret manager/environment, not source control. The frontend is convenience-only; every authorization and ownership rule is enforced by the API/database.
