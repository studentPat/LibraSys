USE librasys;
INSERT INTO roles (role_name) VALUES ('admin'), ('librarian'), ('member')
ON DUPLICATE KEY UPDATE role_name = VALUES(role_name);
INSERT INTO permissions (permission_name) VALUES
('catalog.read'), ('catalog.write'), ('members.read'), ('members.write'),
('circulation.borrow'), ('circulation.return'), ('circulation.reserve'),
('fines.manage'), ('reports.read'), ('users.manage')
ON DUPLICATE KEY UPDATE permission_name = VALUES(permission_name);
