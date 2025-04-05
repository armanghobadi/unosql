import ujson
import uos
import uhashlib
import utime
from cryptolib import aes

class Unosql:
    """
    Unosql: A lightweight, encrypted database for MicroPython.
    Provides collection management with AES encryption support.
    Optimized for production use with error handling and memory efficiency.
    """

    def __init__(self, db_name, encryption_key=None):
        """
        Initialize the database.

        :param db_name: Name of the database (used as file prefix).
        :param encryption_key: Optional 16-byte key for AES encryption/decryption.
        :raises ValueError: If encryption_key is provided but not 16 bytes.
        """
        if encryption_key and len(encryption_key) != 16:
            raise ValueError("Encryption key must be exactly 16 bytes long.")
        self.db_name = db_name
        self.encryption_key = encryption_key
        self.salt_file = f"{db_name}_salt.db"
        self.salt = self._load_salt() if encryption_key else None
        self.data = {}  # In-memory cache for collections
        self._load_existing_collections()

    # --- Core Utility Methods ---

    def _file_exists(self, filepath):
        """Check if a file exists."""
        try:
            uos.stat(filepath)
            return True
        except OSError:
            return False

    def _load_salt(self):
        """Load or generate a unique salt for encryption."""
        if self._file_exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        salt = uos.urandom(16)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        return salt

    def _generate_key(self, password):
        """Generate an AES key using SHA256 and salt."""
        key = password + self.salt
        h = uhashlib.sha256()
        h.update(key)
        return h.digest()[:16]  # Ensure 16-byte key for AES

    def _encrypt(self, data):
        """Encrypt data using AES in ECB mode."""
        key = self._generate_key(self.encryption_key)
        cipher = aes(key, 1)  # ECB mode
        padded_data = self._pad(data.encode('utf-8'))
        return cipher.encrypt(padded_data)

    def _decrypt(self, data):
        """Decrypt data using AES in ECB mode."""
        key = self._generate_key(self.encryption_key)
        cipher = aes(key, 1)
        decrypted_data = cipher.decrypt(data)
        return self._unpad(decrypted_data).decode('utf-8')

    def _pad(self, data):
        """Apply PKCS7 padding to data."""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length]) * padding_length

    def _unpad(self, data):
        """Remove PKCS7 padding from data."""
        padding_length = data[-1]
        if padding_length > 16 or padding_length == 0:
            raise ValueError("Invalid padding")
        return data[:-padding_length]

    def _load_data(self, collection_name):
        """Load collection data from file."""
        file_name = f"{self.db_name}_{collection_name}.db"
        if not self._file_exists(file_name):
            return []
        try:
            with open(file_name, 'rb') as f:
                raw_data = f.read()
                if self.encryption_key:
                    raw_data = self._decrypt(raw_data)
                return ujson.loads(raw_data)
        except (OSError, ValueError, UnicodeError) as e:
            print(f"Error loading {file_name}: {e}")
            return []

    def _save_data(self, collection_name, data):
        """Save collection data to file."""
        file_name = f"{self.db_name}_{collection_name}.db"
        try:
            raw_data = ujson.dumps(data)
            if self.encryption_key:
                raw_data = self._encrypt(raw_data)
            with open(file_name, 'wb') as f:
                f.write(raw_data)
        except (OSError, ValueError) as e:
            print(f"Error saving {file_name}: {e}")

    def _get_existing_collections(self):
        """Get list of existing collection names from files."""
        collections = []
        try:
            for file in uos.listdir():
                if (file.startswith(self.db_name) and file.endswith(".db") and 
                    file != self.salt_file):
                    collection_name = file[len(self.db_name) + 1:-3]
                    collections.append(collection_name)
        except OSError:
            pass  # Ignore directory access errors
        return collections

    def _load_existing_collections(self):
        """Load all existing collections into memory."""
        for collection in self._get_existing_collections():
            self.data[collection] = self._load_data(collection)

    def _get_next_id(self, collection_name):
        """Generate the next unique ID for a collection."""
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        records = self.data[collection_name]
        if not records:
            return 1
        return max(record.get("id", 0) for record in records) + 1

    # --- Public API ---

    def insert(self, collection_name, record):
        """
        Insert a record into a collection with auto-generated ID and timestamp.

        :param collection_name: Name of the collection.
        :param record: Dictionary representing the record.
        :raises ValueError: If record is not a dictionary.
        """
        if not isinstance(record, dict):
            raise ValueError("Record must be a dictionary")
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        
        record = record.copy()  # Avoid modifying the input
        record["id"] = self._get_next_id(collection_name)
        record["timestamp"] = utime.time()
        
        self.data[collection_name].append(record)
        self._save_data(collection_name, self.data[collection_name])

    def find(self, collection_name, key, value):
        """
        Find records matching a key-value pair.

        :param collection_name: Name of the collection.
        :param key: Key to search for.
        :param value: Value to match.
        :return: List of matching records.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        return [record for record in self.data[collection_name] if record.get(key) == value]

    def update(self, collection_name, key, value, new_record):
        """
        Update records matching a key-value pair.

        :param collection_name: Name of the collection.
        :param key: Key to search for.
        :param value: Value to match.
        :param new_record: Dictionary of updated values.
        :return: True if updated, False otherwise.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        updated = False
        for record in self.data[collection_name]:
            if record.get(key) == value:
                record.update(new_record)
                updated = True
        if updated:
            self._save_data(collection_name, self.data[collection_name])
        return updated

    def delete(self, collection_name, key, value):
        """
        Delete records matching a key-value pair.

        :param collection_name: Name of the collection.
        :param key: Key to search for.
        :param value: Value to match.
        :return: Number of deleted records.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        initial_length = len(self.data[collection_name])
        self.data[collection_name] = [
            r for r in self.data[collection_name] if r.get(key) != value
        ]
        deleted = initial_length - len(self.data[collection_name])
        if deleted > 0:
            self._save_data(collection_name, self.data[collection_name])
        return deleted

    def all(self, collection_name):
        """
        Retrieve all records from a collection.

        :param collection_name: Name of the collection.
        :return: List of all records.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name]

    def clear(self, collection_name):
        """
        Clear all records in a collection.

        :param collection_name: Name of the collection.
        """
        self.data[collection_name] = []
        self._save_data(collection_name, self.data[collection_name])

    def count(self, collection_name):
        """
        Count the number of records in a collection.

        :param collection_name: Name of the collection.
        :return: Number of records.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        return len(self.data[collection_name])

    def get_last_n_records(self, collection_name, n):
        """
        Get the last n records from a collection.

        :param collection_name: Name of the collection.
        :param n: Number of records to retrieve.
        :return: List of the last n records.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name][-n:]

    def get_records_in_timeframe(self, collection_name, time_key, start_time, end_time):
        """
        Get records within a specific timeframe.

        :param collection_name: Name of the collection.
        :param time_key: Key representing the timestamp in records.
        :param start_time: Start of the timeframe (Unix timestamp).
        :param end_time: End of the timeframe (Unix timestamp).
        :return: List of records within the timeframe.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        return [
            r for r in self.data[collection_name]
            if start_time <= r.get(time_key, 0) <= end_time
        ]

    def get_first_n_records(self, collection_name, n):
        """
        Get the first n records from a collection.

        :param collection_name: Name of the collection.
        :param n: Number of records to retrieve.
        :return: List of the first n records.
        """
        if collection_name not in self.data:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name][:n]

    def backup(self, backup_file_name):
        """
        Backup the entire database to a single file.

        :param backup_file_name: Name of the backup file.
        """
        backup_data = {}
        for collection in self._get_existing_collections():
            if collection not in self.data:
                self.data[collection] = self._load_data(collection)
            backup_data[collection] = self.data[collection]
        try:
            raw_data = ujson.dumps(backup_data)
            if self.encryption_key:
                raw_data = self._encrypt(raw_data)
            with open(backup_file_name, 'wb') as f:
                f.write(raw_data)
        except (OSError, ValueError) as e:
            print(f"Backup failed: {e}")

    def restore(self, backup_file_name):
        """
        Restore the database from a backup file.

        :param backup_file_name: Name of the backup file.
        :raises OSError: If backup file does not exist or cannot be read.
        """
        if not self._file_exists(backup_file_name):
            raise OSError(f"Backup file '{backup_file_name}' not found")
        try:
            with open(backup_file_name, 'rb') as f:
                raw_data = f.read()
                if self.encryption_key:
                    raw_data = self._decrypt(raw_data)
                backup_data = ujson.loads(raw_data)
            self.data = backup_data
            for collection, records in backup_data.items():
                self._save_data(collection, records)
        except (OSError, ValueError, UnicodeError) as e:
            print(f"Restore failed: {e}")
            raise
