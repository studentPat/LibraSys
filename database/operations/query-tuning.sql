USE librasys;

-- Run in a staging replica with representative data before changing indexes.
EXPLAIN ANALYZE
SELECT b.book_id, b.isbn, b.title, p.publisher_name,
       SUM(c.status = 'available') AS available_copies
FROM books b
LEFT JOIN publishers p ON p.publisher_id = b.publisher_id
LEFT JOIN book_copies c ON c.book_id = b.book_id
WHERE (? IS NULL OR b.title LIKE ? OR b.isbn LIKE ?)
GROUP BY b.book_id, b.isbn, b.title, p.publisher_name
ORDER BY b.title
LIMIT ? OFFSET ?;

EXPLAIN ANALYZE
SELECT br.borrowing_id, m.membership_number, b.title, br.due_at
FROM borrowings br
JOIN members m ON m.member_id = br.member_id
JOIN book_copies c ON c.copy_id = br.copy_id
JOIN books b ON b.book_id = c.book_id
WHERE br.status = 'active' AND br.due_at < UTC_TIMESTAMP()
ORDER BY br.due_at
LIMIT 100;

EXPLAIN ANALYZE
SELECT fine_id, borrowing_id, amount, status, assessed_at
FROM fines
WHERE member_id = ?
ORDER BY assessed_at DESC
LIMIT 100;

EXPLAIN ANALYZE
SELECT reservation_id, member_id, reserved_at
FROM reservations
WHERE book_id = ? AND status = 'queued'
ORDER BY reserved_at
LIMIT 1;

-- Expected supporting indexes:
-- books(ix_books_title), book_copies(ix_book_copies_availability),
-- borrowings(ix_borrowings_due_status), fines(ix_fines_member_status),
-- reservations(ix_reservations_book_queue).
