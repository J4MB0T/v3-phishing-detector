import mysql.connector
from configparser import ConfigParser

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
    return db_config

def remove_duplicates(db_config):
    """Remove duplicate entries in the 'emails' table based on 'message_id'."""
    try:
        cnx = mysql.connector.connect(**db_config)
        cursor = cnx.cursor()

        # Find duplicate message_ids
        cursor.execute("""
            SELECT message_id, MIN(id) AS min_id 
            FROM emails 
            GROUP BY message_id 
            HAVING COUNT(*) > 1
        """)
        duplicates = cursor.fetchall()

        # Remove duplicates, keeping only the first occurrence
        for message_id, min_id in duplicates:
            cursor.execute("""
                DELETE FROM emails 
                WHERE message_id = %s AND id != %s
            """, (message_id, min_id))

        cnx.commit()
        print(f"Removed duplicates for {len(duplicates)} message IDs.")

    except Exception as e:
        print(f"Error removing duplicates: {e}")
        if 'cnx' in locals():
            cnx.rollback()

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'cnx' in locals():
            cnx.close()

if __name__ == "__main__":
    # Load the database configuration
    db_config = load_db_config()

    # Remove duplicates from the database
    remove_duplicates(db_config)
