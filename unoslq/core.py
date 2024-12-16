import ujson
import uos
import uhashlib
import os
from cryptolib import aes

class unoslq:
    def __init__(self, db_name, encryption_key=None):
        """
        Initialize the database with optional encryption.
        :param db_name: The name of the database (used to prefix collection filenames).
        :param encryption_key: The encryption key (can be None for unencrypted database).
        """
        self.db_name = db_name
        self.encryption_key = encryption_key
        self.salt = os.urandom(16)  # Random salt for key derivation
        self.data = {}

    def _file_exists(self, filepath):
        """Check if a file exists in the MicroPython environment."""
        try:
            uos.stat(filepath)
            return True
        except OSError:
            return False

    def _generate_key(self, password, salt):
        """Generate a key using HMAC and SHA256 for encryption."""
        key = password + salt
        h = uhashlib.sha256()
        h.update(key)
        return h.digest()

    def _load_data(self, collection_name):
        """
        Load data from a specific collection.
        :param collection_name: Name of the collection (file).
        :return: List of records in the collection.
        """
        file_name = f"{self.db_name}_{collection_name}.db"
        if not self._file_exists(file_name):
            return []

        with open(file_name, 'rb') as f:
            raw_data = f.read()
            if self.encryption_key:
                raw_data = self._decrypt(raw_data)
            try:
                return ujson.loads(raw_data)
            except ValueError:
                return []

    def _save_data(self, collection_name):
        """
        Save data to a specific collection.
        :param collection_name: Name of the collection (file).
        """
        file_name = f"{self.db_name}_{collection_name}.db"
        raw_data = ujson.dumps(self.data.get(collection_name, []))
        if self.encryption_key:
            raw_data = self._encrypt(raw_data)

        with open(file_name, 'wb') as f:
            f.write(raw_data)

    def _encrypt(self, data):
        """Encrypt data using AES encryption."""
        key = self._generate_key(self.encryption_key, self.salt)
        cipher = aes(key, 1)  # AES in ECB mode (should be CBC or GCM in production)
        padded_data = self._pad(data)
        return cipher.encrypt(padded_data)

    def _decrypt(self, data):
        """Decrypt data using AES decryption."""
        key = self._generate_key(self.encryption_key, self.salt)
        cipher = aes(key, 1)  # AES in ECB mode
        decrypted_data = cipher.decrypt(data)
        return self._unpad(decrypted_data).decode('utf-8')

    def _pad(self, data):
        """Apply PKCS7 padding to the data."""
        padding_length = 16 - (len(data) % 16)
        return data + chr(padding_length) * padding_length

    def _unpad(self, data):
        """Remove PKCS7 padding from the data."""
        padding_length = ord(data[-1:])
        return data[:-padding_length]

    def insert(self, collection_name, record):
        """
        Insert a new record into the specified collection.
        :param collection_name: Name of the collection.
        :param record: A dictionary representing the record.
        """
        if not isinstance(record, dict):
            raise ValueError("Record must be a dictionary.")
        
        if collection_name not in self.data:
            self.data[collection_name] = []
        self.data[collection_name].append(record)
        self._save_data(collection_name)

    def find(self, collection_name, key, value):
        """
        Find records by key-value pair in the specified collection.
        :param collection_name: Name of the collection.
        :param key: Key to search for.
        :param value: Value associated with the key.
        :return: List of matching records.
        """
        return [record for record in self.data.get(collection_name, []) if record.get(key) == value]

    def update(self, collection_name, key, value, new_record):
        """
        Update records that match a key-value pair in the specified collection.
        :param collection_name: Name of the collection.
        :param key: Key to match.
        :param value: Value to match.
        :param new_record: New data to update the record with.
        :return: True if a record was updated, False otherwise.
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
        Delete records matching a key-value pair in the specified collection.
        :param collection_name: Name of the collection.
        :param key: Key to match.
        :param value: Value to match.
        :return: Number of records deleted.
        """
        initial_length = len(self.data.get(collection_name, []))
        self.data[collection_name] = [record for record in self.data.get(collection_name, []) if record.get(key) != value]
        if len(self.data[collection_name]) < initial_length:
            self._save_data(collection_name)
        return initial_length - len(self.data[collection_name])

    def all(self, collection_name):
        """
        Retrieve all records in the specified collection.
        :param collection_name: Name of the collection.
        :return: List of all records.
        """
        return self.data.get(collection_name, [])

    def clear(self, collection_name):
        """
        Clear the entire collection.
        :param collection_name: Name of the collection.
        """
        self.data[collection_name] = []
        self._save_data(collection_name)




