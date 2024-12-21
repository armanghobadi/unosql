import ujson
import uos
import uhashlib
from cryptolib import aes


class unosql:
    """
    unosql: A lightweight encrypted database for MicroPython.
    Provides functionalities to manage collections with encryption support.
    """

    def __init__(self, db_name, encryption_key=None):
        """
        Initialize the database.

        :param db_name: Name of the database (used as the file prefix).
        :param encryption_key: Optional 16-byte key for encryption/decryption.
        """
        if encryption_key and len(encryption_key) != 16:
            raise ValueError("Encryption key must be 16 bytes long.")
        self.db_name = db_name
        self.encryption_key = encryption_key
        self.salt_file = f"{db_name}_salt.db"
        self.salt = self._load_salt() if encryption_key else None
        self.data = {}

    def _load_salt(self):
        """Load or generate a unique salt for encryption."""
        if self._file_exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            salt = uos.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            return salt

    def _file_exists(self, filepath):
        """Check if a file exists."""
        try:
            uos.stat(filepath)
            return True
        except OSError:
            return False

    def _generate_key(self, password):
        """Generate a key using HMAC and SHA256."""
        key = password + self.salt
        h = uhashlib.sha256()
        h.update(key)
        return h.digest()

    def _encrypt(self, data):
        """Encrypt data using AES encryption."""
        key = self._generate_key(self.encryption_key)
        cipher = aes(key, 1)
        padded_data = self._pad(data.encode('utf-8'))
        return cipher.encrypt(padded_data)

    def _decrypt(self, data):
        """Decrypt data using AES encryption."""
        key = self._generate_key(self.encryption_key)
        cipher = aes(key, 1)
        decrypted_data = cipher.decrypt(data)
        return self._unpad(decrypted_data).decode('utf-8')

    def _pad(self, data):
        """Apply PKCS7 padding."""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length]) * padding_length

    def _unpad(self, data):
        """Remove PKCS7 padding."""
        padding_length = data[-1]
        return data[:-padding_length]

    def _load_data(self, collection_name):
        """Load data from a file."""
        file_name = f"{self.db_name}_{collection_name}.db"
        if not self._file_exists(file_name):
            return []
        try:
            with open(file_name, 'rb') as f:
                raw_data = f.read()
                if self.encryption_key:
                    raw_data = self._decrypt(raw_data)
                return ujson.loads(raw_data)
        except (OSError, ValueError):
            return []

    def _save_data(self, collection_name):
        """Save data to a file."""
        file_name = f"{self.db_name}_{collection_name}.db"
        raw_data = ujson.dumps(self.data.get(collection_name, []))
        if self.encryption_key:
            raw_data = self._encrypt(raw_data)
        with open(file_name, 'wb') as f:
            f.write(raw_data)

    def insert(self, collection_name, record):
        """
        Insert a record into a collection.

        :param collection_name: Name of the collection.
        :param record: A dictionary representing the record to insert.
        """
        if not isinstance(record, dict):
            raise ValueError("Record must be a dictionary.")
        if collection_name not in self.data:
            self.data[collection_name] = []
        self.data[collection_name].append(record)
        self._save_data(collection_name)

    def find(self, collection_name, key, value):
        """
        Find records matching a specific key-value pair.

        :param collection_name: Name of the collection.
        :param key: The key to search for.
        :param value: The value to match.
        :return: List of matching records.
        """
        return [record for record in self.data.get(collection_name, []) if record.get(key) == value]

    def update(self, collection_name, key, value, new_record):
        """
        Update records in a collection.

        :param collection_name: Name of the collection.
        :param key: The key to search for.
        :param value: The value to match.
        :param new_record: Dictionary of updated values.
        :return: True if records were updated, False otherwise.
        """
        updated = False
        for record in self.data.get(collection_name, []):
            if record.get(key) == value:
                record.update(new_record)
                updated = True
        if updated:
            self._save_data(collection_name)
        return updated

    def delete(self, collection_name, key, value):
        """
        Delete records matching a specific key-value pair.

        :param collection_name: Name of the collection.
        :param key: The key to search for.
        :param value: The value to match.
        :return: Number of records deleted.
        """
        initial_length = len(self.data.get(collection_name, []))
        self.data[collection_name] = [record for record in self.data.get(collection_name, []) if record.get(key) != value]
        if len(self.data[collection_name]) < initial_length:
            self._save_data(collection_name)
        return initial_length - len(self.data[collection_name])

    def all(self, collection_name):
        """
        Retrieve all records from a collection.

        :param collection_name: Name of the collection.
        :return: List of all records in the collection.
        """
        return self.data.get(collection_name, [])

    def clear(self, collection_name):
        """
        Clear all records in a collection.

        :param collection_name: Name of the collection.
        """
        self.data[collection_name] = []
        self._save_data(collection_name)

    def count(self, collection_name):
        """
        Count the number of records in a collection.

        :param collection_name: Name of the collection.
        :return: Number of records in the collection.
        """
        return len(self.data.get(collection_name, []))
    # Backup the database to a file
    def backup(self, backup_file_name):
        """Backup the entire database."""
        collections = list(self.data.keys())  # Collect all active collections
        for collection in collections:
            self._save_data(collection)  # Ensure all data is saved to disk

        with open(backup_file_name, 'wb') as f:
            for collection in collections:
                file_name = f"{self.db_name}_{collection}.db"
                with open(file_name, 'rb') as coll_file:
                    f.write(coll_file.read())  # Write raw content of each collection to the backup file

    # Restore the database from a backup
    def restore(self, backup_file_name):
        """Restore the database from a backup file."""
        if not self._file_exists(backup_file_name):
            raise FileNotFoundError("Backup file not found.")

        with open(backup_file_name, 'rb') as f:
            content = f.read()  # Read the full backup file content

        # Split and restore data into respective collection files
        collections = list(self.data.keys())  # All existing collections
        for collection in collections:
            file_name = f"{self.db_name}_{collection}.db"
            with open(file_name, 'wb') as coll_file:
                coll_file.write(content)  # Write the backup content to individual files

        # Reload data from disk to memory
        self.data = {collection: self._load_data(collection) for collection in collections}





