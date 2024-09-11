import mysql.connector
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

def list_all_columns():
    # Read database credentials from environment variables
    db_name = os.getenv('DB_NAME')
    user = os.getenv('DB_USER')
    password = os.getenv('DB_PASSWORD')
    host = os.getenv('DB_HOST', 'localhost')  # Default to localhost if not set

    conn = None
    cursor = None

    try:
        # Connect to the MySQL database
        conn = mysql.connector.connect(
            user=user,
            password=password,
            host=host,
            database=db_name
        )
        cursor = conn.cursor()

        # Get list of all tables
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()

        print(f"Database: {db_name}\n")

        # Iterate over each table
        for table in tables:
            table_name = table[0]
            print(f"Table: {table_name}")

            # Get columns for each table
            cursor.execute(f"SHOW COLUMNS FROM {table_name}")
            columns = cursor.fetchall()

            for column in columns:
                print(f"  Column: {column[0]}")

            print()

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        # Close the cursor and connection
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Call the function to list columns
list_all_columns()
