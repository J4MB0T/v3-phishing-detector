
---

# Email Analysis and Phishing Detection System

## Overview

This project is an email analysis and phishing detection system designed to process email files, analyse their content, and store the results in a MySQL database. It includes functionalities for converting EML files to JSON, monitoring changes, inserting data into a database, and removing duplicates. The system also analyses email headers to detect suspicious activity using various criteria and APIs.

## Components

### 1. `eml_to_json.py`

**Purpose:** Converts EML (email) files into JSON format.

**Details:** This script parses EML files and extracts relevant information such as headers, body text, and HTML content. The output JSON file is used for further processing and analysis. This conversion is crucial for standardising email data and making it easier to work with.

### 2. `file_watcher.py`

**Purpose:** Monitors the JSON folder for new or updated files and triggers the insertion of JSON data into the MySQL database.

**Details:** This script uses file system monitoring techniques to watch the JSON folder. When a new JSON file is detected or an existing file is updated, it triggers `insert_jsons.py` to process and insert the data into the database. This ensures that the database is kept up-to-date with the latest email data.

### 3. `insert_jsons.py`

**Purpose:** Inserts JSON data into the MySQL database.

**Details:** This script reads JSON files and inserts the extracted data into the appropriate tables in the MySQL database. It handles the data insertion efficiently and ensures that the data is stored in a structured manner.

### 4. `remove_duplicates.py`

**Purpose:** Handles duplicate data entries in the database.

**Details:** This script checks for and removes duplicate entries from the database to maintain data integrity. It is a critical component for ensuring that the database contains only unique and relevant records, preventing issues caused by redundant data.

### 5. `tables.py`

**Purpose:** Displays the tables in the MySQL database.

**Details:** This script provides a simple interface for listing the tables in the MySQL database. It is useful for database management and verification, allowing users to quickly check the structure of their database.

## Methods Used

### Email Analysis

1. **SPF (Sender Policy Framework) Analysis:**
   - **Purpose:** Verifies that the email is sent from an authorised IP address.
   - **Method:** The SPF result is extracted from the email's authentication results using a regex-based parser. The parsed result indicates whether SPF validation passed or failed.

2. **DKIM (DomainKeys Identified Mail) Analysis:**
   - **Purpose:** Ensures the email's content has not been tampered with during transit.
   - **Method:** The DKIM result is parsed similarly to SPF. This result helps determine if the email's signature is valid.

3. **IP Lookup:**
   - **Purpose:** Provides additional context about the IP address involved in the email.
   - **Method:** Uses APIs from AbuseIPDB and VirusTotal to gather information about the IP address, including abuse confidence scores and detection counts.

4. **Domain Analysis:**
   - **Purpose:** Checks the registration details of the domain associated with the IP address.
   - **Method:** Retrieves domain information using WHOIS lookups to assess if the domain was recently created or if it has a legitimate registration.

5. **Safety Scoring:**
   - **Purpose:** Computes a safety score for the email based on various factors.
   - **Method:** Combines results from SPF, DKIM, and IP lookups to calculate a composite safety score. This score helps assess the potential risk of the email.

## Setup

### Configuration Files

1. **`.env` File:**
   - **Purpose:** Contains environment variables such as database credentials and API keys.
   - **Example Content:**
     ```
     DB_USER=your_db_user
     DB_PASSWORD=your_db_password
     DB_HOST=your_db_host
     DB_NAME=your_db_name
     ABUSEIPDB_KEY=your_abuseipdb_key
     VIRUSTOTAL_KEY=your_virustotal_key
     ```

2. **`config.ini` File:**
   - **Purpose:** Stores configuration settings for database connections and API keys.
   - **Example Content:**
     ```ini
     [mysql]
     user = your_db_user
     password = your_db_password
     host = your_db_host
     database = your_db_name

     [api_keys]
     abuseipdb_key = your_abuseipdb_key
     virustotal_key = your_virustotal_key
     ```

### MySQL Setup

To set up the MySQL database, execute the following SQL commands:

```sql
CREATE DATABASE email_data;

USE email_data;

CREATE TABLE attachments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    type VARCHAR(50),
    size INT
);

CREATE TABLE email_received (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT NOT NULL,
    received_info TEXT
);

CREATE TABLE emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(255),
    in_reply_to VARCHAR(255),
    references TEXT,
    received TEXT,
    authentication_results TEXT,
    received_spf TEXT,
    dkim_signature TEXT,
    list_unsubscribe TEXT,
    `from` VARCHAR(255),
    `to` VARCHAR(255),
    date DATETIME,
    subject VARCHAR(255),
    cc TEXT,
    bcc TEXT,
    body_text TEXT,
    body_html TEXT
);

CREATE TABLE urls (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email_id INT NOT NULL,
    url TEXT
);
```

## Challenges

- **Data Parsing:** Extracting relevant information from EML files required handling various email formats and structures.
- **API Integration:** Integrating with external APIs for IP lookups and domain analysis involved managing API keys and handling rate limits and errors.
- **Data Integrity:** Ensuring the accuracy and uniqueness of data in the database required implementing duplicate checks and handling errors gracefully.

## Conclusion

This project provides a comprehensive solution for analysing and detecting phishing emails. By leveraging various email analysis techniques and external APIs, it helps in identifying suspicious activities and improving email security.

For more details, refer to the code comments and documentation within each file.

---