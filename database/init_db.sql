
CREATE DATABASE IF NOT EXISTS email_db;

USE email_db;

CREATE TABLE IF NOT EXISTS emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_from VARCHAR(255),
    email_to VARCHAR(255),
    subject VARCHAR(255),
    date DATETIME,
    body TEXT,
    ip_addresses TEXT,
    spf_result VARCHAR(255),
    dmarc_result VARCHAR(255),
    dkim_result VARCHAR(255),
    http_links TEXT
);
