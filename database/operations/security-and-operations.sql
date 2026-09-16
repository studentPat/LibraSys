USE librasys;
CREATE USER IF NOT EXISTS 'librasys_runtime'@'%' IDENTIFIED BY 'SET_FROM_SECRET_MANAGER';
CREATE USER IF NOT EXISTS 'librasys_reporting'@'%' IDENTIFIED BY 'SET_FROM_SECRET_MANAGER';
CREATE USER IF NOT EXISTS 'librasys_migrator'@'%' IDENTIFIED BY 'SET_FROM_SECRET_MANAGER';
CREATE USER IF NOT EXISTS 'librasys_dba'@'localhost' IDENTIFIED BY 'SET_FROM_SECRET_MANAGER';
GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON librasys.* TO 'librasys_runtime'@'%';
GRANT SELECT ON librasys.* TO 'librasys_reporting'@'%';
GRANT SELECT, INSERT, ALTER, CREATE, INDEX, REFERENCES ON librasys.* TO 'librasys_migrator'@'%';
-- DBA credentials are provisioned out-of-band and are never placed in application configuration.
