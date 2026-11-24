-- synthetic demo data only
SELECT * FROM customer_accounts;
INSERT INTO users(name, email, ssn) VALUES ('Demo Person', 'demo.person@example.test', '123-45-6789');
CREATE USER reporter IDENTIFIED BY 'Winter2026!';
GRANT ALL ON warehouse.* TO reporter;
DELETE FROM sessions;
SELECT id, total FROM orders WHERE id = 7;
