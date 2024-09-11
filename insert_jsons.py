import json
import mysql.connector
from configparser import ConfigParser
import shutil
import os
from datetime import datetime
import logging
import traceback
from remove_duplicates import remove_duplicates

# Ensure the logs folder exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Setup logging to write logs to the 'logs' folder
logging.basicConfig(
    filename='logs/process_log.log', 
    level=logging.DEBUG,  # Changed to DEBUG for more detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Hardcoded paths for the JSON and archive folders
JSON_FOLDER = 'json'
ARCHIVE_FOLDER = 'archive'

def load_db_config(filename='config.ini', section='mysql'):
    """Load the database configuration from a config file."""
    parser = ConfigParser()
    parser.read(filename)
    db_config = {
        'user': parser.get(section, 'user'),
        'password': parser.get(section, 'password'),
        'host': parser.get(section, 'host'),
        'database': parser.get(section, 'database')
    }
    logging.debug(f"Loaded DB config: {db_config}")
    return db_config

def message_id_exists(cursor, message_id):
    """Check if the message_id already exists in the database."""
    query = "SELECT COUNT(*) FROM emails WHERE message_id = %s"
    logging.debug(f"Executing query: {query} with message_id: {message_id}")
    cursor.execute(query, (message_id,))
    result = cursor.fetchone()
    logging.debug(f"Result of query: {result}")
    return result[0] > 0

def convert_to_mysql_datetime(date_string):
    """Convert the date string from the JSON file to a MySQL-compatible datetime format."""
    try:
        parsed_date = datetime.strptime(date_string, '%a, %d %b %Y %H:%M:%S %z')
        return parsed_date.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError as e:
        logging.error(f"Error parsing date '{date_string}': {e}")
        return None

def list_to_string(lst):
    """Convert a list to a comma-separated string."""
    if lst is None:
        return ''
    return ', '.join(map(str, lst))

def insert_data(json_filename, db_config):
    """Insert data from the JSON file into the database."""
    try:
        logging.info(f"Loading JSON file {json_filename}")
        with open(json_filename, 'r') as file:
            email_data = json.load(file)
        logging.debug(f"Loaded JSON data: {email_data}")

        cnx = mysql.connector.connect(**db_config)
        cursor = cnx.cursor()

        message_id = email_data.get('message_id')
        if message_id_exists(cursor, message_id):
            logging.info(f"Message ID {message_id} already exists. Skipping file {json_filename}.")
            return False

        mysql_date = convert_to_mysql_datetime(email_data.get('date'))
        if mysql_date is None:
            logging.warning(f"Skipping file {json_filename} due to invalid date format.")
            return False

        # Convert lists to strings
        values = (
            message_id,
            email_data.get('in_reply_to', ''),
            list_to_string(email_data.get('references', [])),
            list_to_string(email_data.get('received', [])),
            email_data.get('authentication_results', ''),
            email_data.get('received_spf', ''),
            email_data.get('dkim_signature', ''),
            email_data.get('list_unsubscribe', ''),
            email_data.get('from', ''),
            list_to_string(email_data.get('to', [])),
            mysql_date,
            email_data.get('subject', ''),
            list_to_string(email_data.get('cc', [])),
            list_to_string(email_data.get('bcc', [])),
            email_data.get('body', {}).get('text', ''),
            email_data.get('body', {}).get('html', '')
        )
        logging.debug(f"Values to insert: {values}")

        query = """
            INSERT INTO emails (
                message_id, in_reply_to, `references`, received, authentication_results,
                received_spf, dkim_signature, list_unsubscribe, `from`, `to`, date,
                subject, cc, bcc, body_text, body_html
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        logging.debug(f"Executing query: {query}")
        cursor.execute(query, values)

        cnx.commit()

        email_id = cursor.lastrowid

        # Insert attachments
        for attachment in email_data.get('attachments', []):
            attachment_query = "INSERT INTO attachments (email_id, filename, type, size) VALUES (%s, %s, %s, %s)"
            attachment_values = (email_id, attachment['filename'], attachment['type'], attachment.get('size', 0))
            logging.debug(f"Executing query: {attachment_query} with values: {attachment_values}")
            cursor.execute(attachment_query, attachment_values)

        # Insert URLs
        for url in email_data.get('urls', []):
            url_query = "INSERT INTO urls (email_id, url) VALUES (%s, %s)"
            url_values = (email_id, url)
            logging.debug(f"Executing query: {url_query} with values: {url_values}")
            cursor.execute(url_query, url_values)

        cnx.commit()
        logging.info(f"Inserted data from JSON file {json_filename} into the database successfully.")
        return True

    except Exception as e:
        logging.error(f"Error inserting data from {json_filename}: {e}")
        logging.error("Exception traceback:", exc_info=True)
        if 'cnx' in locals():
            cnx.rollback()
        return False

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'cnx' in locals():
            cnx.close()

def process_files_in_folder(json_folder, archive_folder, db_config):
    """Process all JSON files in the given folder."""
    data_inserted = False
    for filename in os.listdir(json_folder):
        if filename.endswith('.json'):
            json_filename = os.path.join(json_folder, filename)
            logging.info(f"Processing JSON file {json_filename}")
            if insert_data(json_filename, db_config):
                data_inserted = True
                if archive_folder:
                    try:
                        shutil.move(json_filename, os.path.join(archive_folder, filename))
                        logging.info(f"Moved JSON file {filename} to archive.")
                    except Exception as e:
                        logging.error(f"Error moving JSON file {filename} to archive: {e}")

    if data_inserted:
        logging.info("Data was inserted into the database. Running remove_duplicates.py...")
        remove_duplicates(db_config)
        logging.info("Completed duplicate removal process.")
    else:
        logging.info("No data was inserted, skipping remove_duplicates.")

if __name__ == "__main__":
    db_config = load_db_config()

    logging.info("Starting the process to insert JSON files into the database.")

    process_files_in_folder(JSON_FOLDER, ARCHIVE_FOLDER, db_config)

    logging.info("Completed processing all JSON files.")
