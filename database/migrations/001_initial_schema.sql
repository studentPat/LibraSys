CREATE DATABASE IF NOT EXISTS librasys CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE librasys;

CREATE TABLE roles (
    role_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE permissions (
    permission_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(100) NOT NULL UNIQUE
) ENGINE=InnoDB;

CREATE TABLE role_permissions (
    role_id BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(role_id),
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(permission_id)
) ENGINE=InnoDB;

CREATE TABLE users (
    user_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    email VARCHAR(254) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE user_roles (
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(role_id)
) ENGINE=InnoDB;

CREATE TABLE members (
    member_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL UNIQUE,
    membership_number VARCHAR(30) NOT NULL UNIQUE,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(254) NOT NULL UNIQUE,
    phone VARCHAR(30) NULL,
    address VARCHAR(500) NULL,
    status ENUM('active','suspended','closed') NOT NULL DEFAULT 'active',
    joined_at DATE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_members_user FOREIGN KEY (user_id) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE publishers (
    publisher_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    publisher_name VARCHAR(200) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE authors (
    author_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    author_name VARCHAR(200) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_authors_name (author_name)
) ENGINE=InnoDB;

CREATE TABLE categories (
    category_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(100) NOT NULL UNIQUE
) ENGINE=InnoDB;

CREATE TABLE books (
    book_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    isbn VARCHAR(20) NOT NULL UNIQUE,
    title VARCHAR(300) NOT NULL,
    subtitle VARCHAR(300) NULL,
    publisher_id BIGINT UNSIGNED NULL,
    publication_year SMALLINT UNSIGNED NULL,
    description TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_books_publisher FOREIGN KEY (publisher_id) REFERENCES publishers(publisher_id),
    CONSTRAINT ck_books_year CHECK (publication_year IS NULL OR publication_year BETWEEN 1000 AND 2100),
    INDEX ix_books_title (title)
) ENGINE=InnoDB;

CREATE TABLE book_authors (
    book_id BIGINT UNSIGNED NOT NULL,
    author_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (book_id, author_id),
    CONSTRAINT fk_book_authors_book FOREIGN KEY (book_id) REFERENCES books(book_id) ON DELETE CASCADE,
    CONSTRAINT fk_book_authors_author FOREIGN KEY (author_id) REFERENCES authors(author_id)
) ENGINE=InnoDB;

CREATE TABLE book_categories (
    book_id BIGINT UNSIGNED NOT NULL,
    category_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (book_id, category_id),
    CONSTRAINT fk_book_categories_book FOREIGN KEY (book_id) REFERENCES books(book_id) ON DELETE CASCADE,
    CONSTRAINT fk_book_categories_category FOREIGN KEY (category_id) REFERENCES categories(category_id)
) ENGINE=InnoDB;

CREATE TABLE book_copies (
    copy_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    book_id BIGINT UNSIGNED NOT NULL,
    barcode VARCHAR(50) NOT NULL UNIQUE,
    status ENUM('available','on_loan','reserved','lost','maintenance') NOT NULL DEFAULT 'available',
    acquired_at DATE NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 0,
    CONSTRAINT fk_book_copies_book FOREIGN KEY (book_id) REFERENCES books(book_id),
    INDEX ix_book_copies_availability (book_id, status)
) ENGINE=InnoDB;

CREATE TABLE borrowings (
    borrowing_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    copy_id BIGINT UNSIGNED NOT NULL,
    member_id BIGINT UNSIGNED NOT NULL,
    borrowed_at DATETIME NOT NULL,
    due_at DATETIME NOT NULL,
    returned_at DATETIME NULL,
    status ENUM('active','returned','overdue','lost') NOT NULL DEFAULT 'active',
    returned_condition ENUM('good','damaged','lost') NULL,
    idempotency_key VARCHAR(100) NOT NULL UNIQUE,
    created_by BIGINT UNSIGNED NOT NULL,
    CONSTRAINT fk_borrowings_copy FOREIGN KEY (copy_id) REFERENCES book_copies(copy_id),
    CONSTRAINT fk_borrowings_member FOREIGN KEY (member_id) REFERENCES members(member_id),
    CONSTRAINT fk_borrowings_creator FOREIGN KEY (created_by) REFERENCES users(user_id),
    INDEX ix_borrowings_member_status (member_id, status),
    INDEX ix_borrowings_due_status (due_at, status)
) ENGINE=InnoDB;

CREATE TABLE reservations (
    reservation_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    book_id BIGINT UNSIGNED NOT NULL,
    member_id BIGINT UNSIGNED NOT NULL,
    reserved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    status ENUM('queued','ready','fulfilled','cancelled','expired') NOT NULL DEFAULT 'queued',
    idempotency_key VARCHAR(100) NOT NULL UNIQUE,
    CONSTRAINT fk_reservations_book FOREIGN KEY (book_id) REFERENCES books(book_id),
    CONSTRAINT fk_reservations_member FOREIGN KEY (member_id) REFERENCES members(member_id),
    INDEX ix_reservations_book_queue (book_id, status, reserved_at)
) ENGINE=InnoDB;

CREATE TABLE fines (
    fine_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    borrowing_id BIGINT UNSIGNED NULL,
    member_id BIGINT UNSIGNED NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    reason VARCHAR(255) NOT NULL,
    status ENUM('unpaid','partially_paid','paid','waived') NOT NULL DEFAULT 'unpaid',
    assessed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_fines_borrowing FOREIGN KEY (borrowing_id) REFERENCES borrowings(borrowing_id),
    CONSTRAINT fk_fines_member FOREIGN KEY (member_id) REFERENCES members(member_id),
    CONSTRAINT ck_fines_amount CHECK (amount > 0),
    INDEX ix_fines_member_status (member_id, status)
) ENGINE=InnoDB;

CREATE TABLE payments (
    payment_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    fine_id BIGINT UNSIGNED NOT NULL,
    member_id BIGINT UNSIGNED NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    payment_reference VARCHAR(100) NOT NULL UNIQUE,
    paid_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    received_by BIGINT UNSIGNED NOT NULL,
    CONSTRAINT fk_payments_fine FOREIGN KEY (fine_id) REFERENCES fines(fine_id),
    CONSTRAINT fk_payments_member FOREIGN KEY (member_id) REFERENCES members(member_id),
    CONSTRAINT fk_payments_receiver FOREIGN KEY (received_by) REFERENCES users(user_id),
    CONSTRAINT ck_payments_amount CHECK (amount > 0)
) ENGINE=InnoDB;

CREATE TABLE sessions (
    session_id CHAR(36) PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash BINARY(32) NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    INDEX ix_sessions_expiry (expires_at, revoked_at)
) ENGINE=InnoDB;

CREATE TABLE audit_logs (
    audit_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    actor_user_id BIGINT UNSIGNED NULL,
    action_name VARCHAR(100) NOT NULL,
    entity_name VARCHAR(100) NOT NULL,
    entity_id VARCHAR(100) NULL,
    details_json JSON NULL,
    occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARBINARY(16) NULL,
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id) REFERENCES users(user_id),
    INDEX ix_audit_entity (entity_name, entity_id, occurred_at),
    INDEX ix_audit_occurred (occurred_at)
) ENGINE=InnoDB;

CREATE VIEW available_book_copies AS
SELECT c.copy_id, c.book_id, b.isbn, b.title, c.barcode
FROM book_copies c JOIN books b ON b.book_id = c.book_id
WHERE c.status = 'available';
