import os
import time
import subprocess
import shutil
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Setup logging
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(filename=os.path.join(log_dir, 'file_watcher.log'), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WatcherHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.json'):
            logger.info(f"New JSON file detected: {event.src_path}")
            json_file_path = event.src_path
            archive_folder = 'archive'
            os.makedirs(archive_folder, exist_ok=True)
            
            try:
                # Run the insert_jsons.py script with the JSON file
                result = subprocess.run(['python3', 'insert_jsons.py', json_file_path, archive_folder], check=True, capture_output=True, text=True)
                logger.info(f"insert_jsons.py output:\n{result.stdout}")

                # Move the JSON file to the archive folder
                archive_path = os.path.join(archive_folder, os.path.basename(json_file_path))
                shutil.move(json_file_path, archive_path)
                logger.info(f"Moved JSON file {json_file_path} to archive as {archive_path}")
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Error running insert_jsons.py: {e}\nScript error output: {e.stderr}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}")

def start_watching(folder):
    event_handler = WatcherHandler()
    observer = Observer()
    observer.schedule(event_handler, folder, recursive=False)
    observer.start()
    logger.info(f"Started watching folder: {folder}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_watching('json')
