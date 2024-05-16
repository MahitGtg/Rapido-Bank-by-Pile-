import os
import random
import time
import hashlib
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import schedule
import yara

# Constants
BLOCK_SIZE = 16
KEY_FILE = "encryption.key"
DATA_FILE = "data.enc"
WATCH_PATH = "/home/william/project/rapidoBank/files"
YARA_RULES_FILE = "/home/william/project/rapidoBank/rules.yara"

# Hash algorithms available
HASH_ALGORITHMS = ["sha256", "sha512", "md5"]

# Logging configuration with colors
class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Setting up custom logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

# Function to generate a new encryption key
def generate_key(size=50):
    return os.urandom(size)

# Function to save the key securely
def save_key(key, path=KEY_FILE):
    with open(path, "wb") as key_file:
        key_file.write(key)
    logger.info(f"Encryption key saved in {path}")

# Function to load the key securely
def load_key(path=KEY_FILE):
    try:
        with open(path, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        logger.error(f"Key file {path} not found.")
        return None

# Simple XOR encryption function (for demonstration purposes only)
def xor_cipher(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Function to encrypt data
def encrypt_data(data, key):
    logger.info("Encrypting data")
    return xor_cipher(data, key)

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    logger.info("Decrypting data")
    return xor_cipher(encrypted_data, key)

# Function to change the encryption key
def change_encryption_key():
    logger.info("Starting encryption key change process...")
    try:
        # Load current encrypted data
        with open(DATA_FILE, "rb") as file:
            encrypted_data = file.read()
        current_key = load_key()
        if current_key:
            decrypted_data = decrypt_data(encrypted_data, current_key)
        else:
            decrypted_data = b"Initial data"
    except (FileNotFoundError, ValueError):
        decrypted_data = b"Initial data"

    # Generate new key
    new_key = generate_key()
    save_key(new_key)

    # Encrypt data using the new key
    new_encrypted_data = encrypt_data(decrypted_data, new_key)
    with open(DATA_FILE, "wb") as file:
        file.write(new_encrypted_data)

    logger.info("Switched to a new encryption key.")

# Function to hash a file using a random algorithm
def hash_file(file_path):
    algorithm = random.choice(HASH_ALGORITHMS)
    hash_func = getattr(hashlib, algorithm)()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        file_hash = hash_func.hexdigest()
        logger.info(f"Using {algorithm} to hash {file_path}, hash: {file_hash}")
        return file_hash
    except FileNotFoundError:
        logger.error(f"File {file_path} not found.")
        return None

# Function to scan a file with Yara individually
def yara_scan_individual(file_path):
    rules = yara.compile(filepath=YARA_RULES_FILE)
    matches = rules.match(file_path)
    if matches:
        logger.warning(f"Yara alert for {file_path}: {[match.rule for match in matches]}")
        # Trigger additional actions based on Yara alert, e.g., change encryption key
        change_encryption_key()
        generate_security_recommendations(matches, file_path)
    return matches

# Function to generate security recommendations
def generate_security_recommendations(matches, file_path):
    recommendations = []
    for match in matches:
        if match.rule == "General_Malware_Scan":
            recommendations.append(f"Malware detected in {file_path}. Ensure the file is removed or cleaned.")
        elif match.rule == "HiddenSensitiveFiles":
            recommendations.append(f"Sensitive information found in {file_path}. Consider encrypting this file.")
        elif match.rule == "DetectMaliciousScripts":
            recommendations.append(f"Script detected in {file_path}. Verify the script is safe to execute.")
        elif match.rule == "NetworkAccessExecutable":
            recommendations.append(f"Executable file detected in {file_path}. Ensure it is from a trusted source.")
        elif match.rule == "DetectMaliciousURLs":
            recommendations.append(f"Malicious URL detected in {file_path}. Block the URL and investigate its source.")
        elif match.rule == "Detect_Custom_Signatures":
            recommendations.append(f"Custom signature detected in {file_path}. Investigate and ensure it's expected.")
        elif match.rule == "WannaCry_Ransomware":
            recommendations.append(f"WannaCry ransomware detected in {file_path}. Ensure the file is removed and take necessary actions.")

    for recommendation in recommendations:
        logger.warning(f"Security recommendation: {recommendation}")

# Periodic encryption key change
def periodic_encryption_key_change():
    logger.info("Changing encryption key due to periodic schedule")
    change_encryption_key()

# Watchdog event handler to trigger hashing and Yara scanning on file modifications
class FileSystemHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return  # Ignore directory events
        if event.event_type in ['modified', 'created', 'deleted']:
            logger.info(f"File event detected: {event.event_type} - {event.src_path}")
            hash_file(event.src_path)
            yara_scan_individual(event.src_path)

# Set up watchdog to monitor filesystem changes
def setup_filesystem_watcher(path=WATCH_PATH):
    observer = Observer()
    event_handler = FileSystemHandler()
    observer.schedule(event_handler, path=path, recursive=True)
    observer.start()
    logger.info(f"Started watching {path} for changes")
    return observer

# Function to scan all existing files in the directory
def scan_existing_files(path=WATCH_PATH):
    logger.info("Scanning all existing files in the directory...")
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            logger.info(f"Scanning existing file: {file_path}")
            hash_file(file_path)
            yara_scan_individual(file_path)
    logger.info("Finished scanning existing files.")

# Schedule the encryption key change periodically
schedule.every(10).minutes.do(periodic_encryption_key_change)

# Initial setup of encryption key if it doesn't already exist
if not os.path.exists(KEY_FILE):
    initial_key = generate_key()
    save_key(initial_key)
    with open(DATA_FILE, "wb") as file:
        file.write(encrypt_data(b"Initial data", initial_key))
    logger.info(f"Initial encryption key saved in {KEY_FILE}")

# Scan all existing files in the directory
scan_existing_files()

# Set up the filesystem watcher
observer = setup_filesystem_watcher()

# Main loop to keep checking scheduled tasks and file changes
try:
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
