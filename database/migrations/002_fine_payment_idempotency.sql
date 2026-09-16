USE librasys;

ALTER TABLE fines ADD COLUMN idempotency_key VARCHAR(100) NULL;
UPDATE fines SET idempotency_key = CONCAT('legacy-fine-', fine_id) WHERE idempotency_key IS NULL;
ALTER TABLE fines MODIFY idempotency_key VARCHAR(100) NOT NULL;
ALTER TABLE fines ADD CONSTRAINT uq_fines_idempotency UNIQUE (idempotency_key);
