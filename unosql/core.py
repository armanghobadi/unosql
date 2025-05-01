import ujson
import uos
import uhashlib
import utime
import ubinascii
from cryptolib import aes

class Unosql:
    """
    Unosql: Advanced NoSQL database for MicroPython with AES-CBC encryption,
    optional data compression (uzlib), multi-indexing, versioning, and robust concurrency.
    Falls back to no compression if uzlib is unavailable.
    """

    # Constants
    MAX_LOG_SIZE = 10240  # Max log file size in bytes
    LOCK_TIMEOUT = 5000   # Lock timeout in milliseconds
    SALT_SIZE = 16        # Salt size in bytes
    IV_SIZE = 16          # IV size for AES-CBC
    HMAC_SIZE = 32        # HMAC-SHA256 size
    MIN_KEY_LENGTH = 16   # Minimum encryption key length
    DEFAULT_ITERATIONS = 10000  # Default PBKDF2 iterations

    def __init__(self, db_name, encryption_key=None, iterations=DEFAULT_ITERATIONS, log_level="INFO"):
        """
        Initialize the database with advanced features.

        :param db_name: Database name used as file prefix.
        :param encryption_key: Optional 16-byte key for AES-CBC encryption.
        :param iterations: Number of PBKDF2 iterations for key derivation.
        :param log_level: Logging level (DEBUG, INFO, ERROR).
        :raises ValueError: If encryption_key or parameters are invalid.
        """
        if encryption_key and len(encryption_key) != self.MIN_KEY_LENGTH:
            raise ValueError(f"Encryption key must be {self.MIN_KEY_LENGTH} bytes.")
        if not db_name:
            raise ValueError("Database name cannot be empty.")
        self.db_name = self._sanitize_name(db_name)
        self.encryption_key = encryption_key
        self.iterations = max(1, iterations)
        self.log_level = log_level.upper()
        self.salt_file = f"{self.db_name}_salt.db"
        self.salt = self._load_salt() if encryption_key else None
        self.data = {}  # Lazy-loaded collections
        self.indexes = {}  # Multi-key indexes
        self.locks = {}  # Concurrency locks
        self.hmac_key = self._derive_hmac_key() if encryption_key else None
        self._initialize_logging()
        self._load_existing_collections()
        self._log("INFO", f"Database {self.db_name} initialized with {self.iterations} iterations.")

    # --- Utility Methods ---

    def _sanitize_name(self, name):
        """Sanitize names to prevent injection attacks."""
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        sanitized = "".join(c for c in name if c in allowed)
        if not sanitized:
            raise ValueError("Sanitized name is empty.")
        return sanitized

    def _file_exists(self, filepath):
        """Check if a file exists."""
        try:
            uos.stat(filepath)
            return True
        except OSError:
            return False

    def _load_salt(self):
        """Load or generate a random salt for key derivation."""
        if self._file_exists(self.salt_file):
            try:
                with open(self.salt_file, 'rb') as f:
                    return f.read()
            except OSError as e:
                self._log("ERROR", f"Failed to read salt file: {e}")
                raise
        salt = uos.urandom(self.SALT_SIZE)
        try:
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            self._log("INFO", "Generated new salt.")
        except OSError as e:
            self._log("ERROR", f"Failed to write salt file: {e}")
            raise
        return salt

    def _derive_key(self, password):
        """Derive AES key using PBKDF2-like iteration with SHA256."""
        key = password + self.salt
        for _ in range(self.iterations):
            h = uhashlib.sha256()
            h.update(key)
            key = h.digest()
        return key[:self.MIN_KEY_LENGTH]

    def _derive_hmac_key(self):
        """Derive a separate key for HMAC-SHA256."""
        if not self.encryption_key:
            return None
        return self._derive_key(self.encryption_key + b"hmac")

    def _compute_hmac(self, data):
        """Compute HMAC-SHA256 for data authentication."""
        if not self.hmac_key:
            return b""
        h = uhashlib.sha256()
        h.update(self.hmac_key + data)
        return h.digest()

    def _verify_hmac(self, data, hmac):
        """Verify HMAC-SHA256 for data integrity."""
        return self._compute_hmac(data) == hmac

    def _encrypt(self, data):
        """Encrypt data using AES-CBC with HMAC authentication."""
        if not self.encryption_key:
            return data.encode('utf-8')
        key = self._derive_key(self.encryption_key)
        iv = uos.urandom(self.IV_SIZE)
        cipher = aes(key, 2, iv)  # CBC mode
        padded = self._pad(data.encode('utf-8'))
        ciphertext = cipher.encrypt(padded)
        hmac = self._compute_hmac(ciphertext)
        return iv + hmac + ciphertext

    def _decrypt(self, data):
        """Decrypt data using AES-CBC with HMAC verification."""
        if not self.encryption_key:
            return data.decode('utf-8')
        iv = data[:self.IV_SIZE]
        hmac = data[self.IV_SIZE:self.IV_SIZE + self.HMAC_SIZE]
        ciphertext = data[self.IV_SIZE + self.HMAC_SIZE:]
        if not self._verify_hmac(ciphertext, hmac):
            self._log("ERROR", "HMAC verification failed.")
            raise ValueError("Data integrity check failed.")
        key = self._derive_key(self.encryption_key)
        cipher = aes(key, 2, iv)  # CBC mode
        decrypted = cipher.decrypt(ciphertext)
        return self._unpad(decrypted).decode('utf-8')

    def _pad(self, data):
        """Apply PKCS7 padding."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len]) * pad_len

    def _unpad(self, data):
        """Remove PKCS7 padding."""
        pad_len = data[-1]
        if pad_len > 16 or pad_len == 0:
            self._log("ERROR", "Invalid padding detected.")
            raise ValueError("Invalid padding")
        return data[:-pad_len]

    def _compress(self, data):
        """Compress data using uzlib if available, else return unchanged."""
        try:
            import uzlib
            self._log("DEBUG", "Using uzlib for compression")
            return uzlib.compress(data)
        except ImportError:
            self._log("DEBUG", "uzlib not available, skipping compression")
            return data

    def _decompress(self, data):
        """Decompress data using uzlib if compressed, else return unchanged."""
        try:
            import uzlib
            self._log("DEBUG", "Using uzlib for decompression")
            return uzlib.decompress(data)
        except ImportError:
            self._log("DEBUG", "uzlib not available, assuming uncompressed data")
            return data

    def _initialize_logging(self):
        """Initialize logging system with rotation."""
        log_file = f"{self.db_name}_errors.log"
        try:
            if self._file_exists(log_file):
                stat = uos.stat(log_file)
                if stat[6] > self.MAX_LOG_SIZE:
                    uos.rename(log_file, f"{log_file}.{utime.time()}")
                    self._log("INFO", "Log file rotated due to size limit.")
        except OSError as e:
            self._log("ERROR", f"Failed to initialize logging: {e}")

    def _log(self, level, message):
        """Log messages with specified level."""
        if level not in ("DEBUG", "INFO", "ERROR"):
            return
        if (self.log_level == "ERROR" and level != "ERROR") or \
           (self.log_level == "INFO" and level == "DEBUG"):
            return
        try:
            with open(f"{self.db_name}_errors.log", 'a') as f:
                f.write(f"[{utime.time()}] {level}: {message}\n")
        except OSError as e:
            print(f"Log error: {e}")

    def _acquire_lock(self, collection_name, timeout_ms=LOCK_TIMEOUT):
        """Acquire a file lock with timeout."""
        lock_file = f"{self.db_name}_{collection_name}.lock"
        start_time = utime.ticks_ms()
        while self._file_exists(lock_file):
            if utime.ticks_diff(utime.ticks_ms(), start_time) > timeout_ms:
                self._log("ERROR", f"Lock timeout for {collection_name}")
                raise OSError(f"Lock timeout for {collection_name}")
            utime.sleep_ms(10)
        try:
            with open(lock_file, 'wb') as f:
                f.write(b'locked')
            self.locks[collection_name] = lock_file
            self._log("DEBUG", f"Lock acquired for {collection_name}")
        except OSError as e:
            self._log("ERROR", f"Failed to acquire lock for {collection_name}: {e}")
            raise

    def _release_lock(self, collection_name):
        """Release a file lock."""
        if collection_name in self.locks:
            try:
                uos.remove(self.locks[collection_name])
                del self.locks[collection_name]
                self._log("DEBUG", f"Lock released for {collection_name}")
            except OSError as e:
                self._log("ERROR", f"Failed to release lock for {collection_name}: {e}")

    def _load_data(self, collection_name):
        """Load collection data with lazy loading and compression."""
        file_name = f"{self.db_name}_{collection_name}.db"
        if not self._file_exists(file_name):
            self._log("INFO", f"No data file for {collection_name}")
            return []
        try:
            self._acquire_lock(collection_name)
            with open(file_name, 'rb') as f:
                raw_data = f.read()
            raw_data = self._decompress(raw_data)
            if self.encryption_key:
                raw_data = self._decrypt(raw_data)
            data = ujson.loads(raw_data)
            self._validate_records(data)
            self._log("INFO", f"Loaded {len(data)} records from {collection_name}")
            return data
        except (OSError, ValueError, UnicodeError) as e:
            self._log("ERROR", f"Error loading {file_name}: {e}")
            return []
        finally:
            self._release_lock(collection_name)

    def _save_data(self, collection_name, data):
        """Save collection data with atomic operation and compression."""
        file_name = f"{self.db_name}_{collection_name}.db"
        temp_file = f"{file_name}.tmp"
        try:
            self._acquire_lock(collection_name)
            self._validate_records(data)
            raw_data = ujson.dumps(data)
            if self.encryption_key:
                raw_data = self._encrypt(raw_data)
            raw_data = self._compress(raw_data)
            with open(temp_file, 'wb') as f:
                f.write(raw_data)
            uos.rename(temp_file, file_name)
            self._update_indexes(collection_name, data)
            self._log("INFO", f"Saved {len(data)} records to {collection_name}")
        except (OSError, ValueError) as e:
            self._log("ERROR", f"Error saving {file_name}: {e}")
            raise
        finally:
            self._release_lock(collection_name)

    def _validate_records(self, records):
        """Validate record types and structure."""
        if not isinstance(records, list):
            raise ValueError("Records must be a list.")
        for rec in records:
            if not isinstance(rec, dict):
                raise ValueError("Each record must be a dictionary.")
            for k, v in rec.items():
                if not isinstance(k, str):
                    raise ValueError(f"Record key must be a string, got {type(k)}")
                if not self._is_valid_type(v):
                    raise ValueError(f"Invalid data type for key {k}: {type(v)}")

    def _is_valid_type(self, value):
        """Check if value is a supported data type."""
        return isinstance(value, (str, int, float, bool, list, dict, type(None)))

    def _get_existing_collections(self):
        """Retrieve list of existing collections."""
        collections = []
        try:
            for file in uos.listdir():
                if (file.startswith(self.db_name) and file.endswith(".db") and
                    file != self.salt_file and not file.endswith(".lock")):
                    collections.append(file[len(self.db_name) + 1:-3])
            self._log("DEBUG", f"Found collections: {collections}")
        except OSError as e:
            self._log("ERROR", f"Error listing collections: {e}")
        return collections

    def _load_existing_collections(self):
        """Initialize collections for lazy loading."""
        for collection in self._get_existing_collections():
            self.data[collection] = None
            self.indexes[collection] = {}
        self._log("INFO", f"Initialized {len(self.data)} collections.")

    def _build_index(self, collection_name, key):
        """Build index for a single or compound key."""
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        index = {}
        for i, record in enumerate(self.data[collection_name]):
            value = record.get(key)
            if value is not None:
                index.setdefault(value, []).append(i)
        self.indexes[collection_name][key] = index
        self._log("DEBUG", f"Built index for {key} in {collection_name}")

    def _build_compound_index(self, collection_name, keys):
        """Build compound index for multiple keys."""
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        index = {}
        for i, record in enumerate(self.data[collection_name]):
            value = tuple(record.get(k) for k in keys)
            if all(v is not None for v in value):
                index.setdefault(value, []).append(i)
        index_key = ":".join(keys)
        self.indexes[collection_name][index_key] = index
        self._log("DEBUG", f"Built compound index {index_key} in {collection_name}")

    def _update_indexes(self, collection_name, data):
        """Update all indexes after data modification."""
        for key in self.indexes.get(collection_name, {}):
            if ":" in key:
                self._build_compound_index(collection_name, key.split(":"))
            else:
                self._build_index(collection_name, key)

    def _next_id(self, collection_name):
        """Generate next unique ID for records."""
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        records = self.data[collection_name]
        max_id = max((record.get("id", 0) for record in records), default=0)
        return max_id + 1

    def _unload_collection(self, collection_name):
        """Unload collection from memory to free resources."""
        if collection_name in self.data and self.data[collection_name] is not None:
            self._save_data(collection_name, self.data[collection_name])
            self.data[collection_name] = []
            self._log("INFO", f"Unloaded collection {collection_name} from memory.")

    # --- Public API ---

    def create_index(self, collection_name, keys):
        """
        Create single or compound index for keys.

        :param collection_name: Name of the collection.
        :param keys: Single key (str) or list of keys for compound index.
        """
        collection_name = self._sanitize_name(collection_name)
        if not isinstance(keys, (str, list)):
            raise ValueError("Keys must be a string or list of strings.")
        if isinstance(keys, str):
            keys = [keys]
        if not all(isinstance(k, str) for k in keys):
            raise ValueError("All keys must be strings.")
        if collection_name not in self.indexes:
            self.indexes[collection_name] = {}
        if len(keys) == 1:
            self._build_index(collection_name, keys[0])
        else:
            self._build_compound_index(collection_name, keys)

    def insert(self, collection_name, record):
        """
        Insert a record with ID, timestamp, and version.

        :param collection_name: Name of the collection.
        :param record: Dictionary representing the record.
        :raises ValueError: If record is invalid.
        """
        collection_name = self._sanitize_name(collection_name)
        if not isinstance(record, dict):
            raise ValueError("Record must be a dictionary.")
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        record = record.copy()
        record["id"] = self._next_id(collection_name)
        record["timestamp"] = utime.time()
        record["version"] = 1
        self._validate_records([record])
        self.data[collection_name].append(record)
        self._save_data(collection_name, self.data[collection_name])

    def find(self, collection_name, key, value):
        """
        Find records using index if available.

        :param collection_name: Name of the collection.
        :param key: Key or list of keys for compound search.
        :param value: Value or tuple of values to match.
        :return: List of matching records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        if isinstance(key, list):
            key_str = ":".join(key)
            if key_str in self.indexes.get(collection_name, {}):
                indexes = self.indexes[collection_name][key_str].get(tuple(value), [])
                return [self.data[collection_name][i] for i in indexes]
            return [r for r in self.data[collection_name] if all(r.get(k) == v for k, v in zip(key, value))]
        if key in self.indexes.get(collection_name, {}):
            indexes = self.indexes[collection_name][key].get(value, [])
            return [self.data[collection_name][i] for i in indexes]
        return [r for r in self.data[collection_name] if r.get(key) == value]

    def update(self, collection_name, key, value, new_record):
        """
        Update records with versioning.

        :param collection_name: Name of the collection.
        :param key: Key to search for.
        :param value: Value to match.
        :param new_record: Dictionary of updated values.
        :return: True if updated, False otherwise.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        updated = False
        for record in self.data[collection_name]:
            if record.get(key) == value:
                record.update(new_record)
                record["version"] = record.get("version", 1) + 1
                record["timestamp"] = utime.time()
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
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        initial_len = len(self.data[collection_name])
        self.data[collection_name] = [r for r in self.data[collection_name] if r.get(key) != value]
        deleted = initial_len - len(self.data[collection_name])
        if deleted > 0:
            self._save_data(collection_name, self.data[collection_name])
        return deleted

    def all(self, collection_name):
        """
        Retrieve all records from a collection.

        :param collection_name: Name of the collection.
        :return: List of all records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name]

    def clear(self, collection_name):
        """
        Clear all records in a collection.

        :param collection_name: Name of the collection.
        """
        collection_name = self._sanitize_name(collection_name)
        self.data[collection_name] = []
        self.indexes[collection_name] = {}
        self._save_data(collection_name, self.data[collection_name])

    def count(self, collection_name):
        """
        Count the number of records in a collection.

        :param collection_name: Name of the collection.
        :return: Number of records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return len(self.data[collection_name])

    def get_last_n_records(self, collection_name, n):
        """
        Get the last n records from a collection.

        :param collection_name: Name of the collection.
        :param n: Number of records to retrieve.
        :return: List of the last n records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name][-n:]

    def get_records_in_timeframe(self, collection_name, time_key, start_time, end_time):
        """
        Get records within a specific timeframe.

        :param collection_name: Name of the collection.
        :param time_key: Key representing the timestamp.
        :param start_time: Start of the timeframe (Unix timestamp).
        :param end_time: End of the timeframe (Unix timestamp).
        :return: List of records within the timeframe.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return [r for r in self.data[collection_name] if start_time <= r.get(time_key, 0) <= end_time]

    def get_first_n_records(self, collection_name, n):
        """
        Get the first n records from a collection.

        :param collection_name: Name of the collection.
        :param n: Number of records to retrieve.
        :return: List of the first n records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name][:n]

    def backup(self, backup_file_name):
        """
        Backup the database with integrity check and compression.

        :param backup_file_name: Name of the backup file.
        :raises OSError: If backup fails.
        """
        backup_data = {}
        for collection in self._get_existing_collections():
            if collection not in self.data or self.data[collection] is None:
                self.data[collection] = self._load_data(collection)
            backup_data[collection] = self.data[collection]
        try:
            raw_data = ujson.dumps(backup_data)
            if self.encryption_key:
                raw_data = self._encrypt(raw_data)
            raw_data = self._compress(raw_data)
            checksum = uhashlib.sha256(raw_data).digest()
            with open(backup_file_name, 'wb') as f:
                f.write(checksum + raw_data)
            if not self._file_exists(backup_file_name):
                raise OSError(f"Failed to create backup file {backup_file_name}")
            self._log("INFO", f"Backup created: {backup_file_name}")
        except (OSError, ValueError) as e:
            self._log("ERROR", f"Backup failed: {e}")
            raise

    def restore(self, backup_file_name):
        """
        Restore the database from a backup file with integrity check.

        :param backup_file_name: Name of the backup file.
        :raises OSError: If restore fails.
        """
        if not self._file_exists(backup_file_name):
            self._log("ERROR", f"Backup file not found: {backup_file_name}")
            raise OSError(f"Backup file {backup_file_name} not found")
        try:
            with open(backup_file_name, 'rb') as f:
                data = f.read()
            checksum, raw_data = data[:32], data[32:]
            if uhashlib.sha256(raw_data).digest() != checksum:
                self._log("ERROR", "Backup file corrupted")
                raise ValueError("Backup file corrupted")
            raw_data = self._decompress(raw_data)
            if self.encryption_key:
                raw_data = self._decrypt(raw_data)
            backup_data = ujson.loads(raw_data)
            self.data = {k: None for k in backup_data}
            self.indexes = {k: {} for k in backup_data}
            for collection, records in backup_data.items():
                self._save_data(collection, records)
            self._log("INFO", f"Restored from backup: {backup_file_name}")
        except (OSError, ValueError, UnicodeError) as e:
            self._log("ERROR", f"Restore failed: {e}")
            raise

    def incremental_backup(self, backup_file_name, since_timestamp):
        """
        Create an incremental backup of records modified since a timestamp.

        :param backup_file_name: Name of the backup file.
        :param since_timestamp: Unix timestamp for incremental backup.
        """
        backup_data = {}
        for collection in self._get_existing_collections():
            if collection not in self.data or self.data[collection] is None:
                self.data[collection] = self._load_data(collection)
            backup_data[collection] = [
                r for r in self.data[collection] if r.get("timestamp", 0) >= since_timestamp
            ]
        try:
            raw_data = ujson.dumps(backup_data)
            if self.encryption_key:
                raw_data = self._encrypt(raw_data)
            raw_data = self._compress(raw_data)
            checksum = uhashlib.sha256(raw_data).digest()
            with open(backup_file_name, 'wb') as f:
                f.write(checksum + raw_data)
            self._log("INFO", f"Incremental backup created: {backup_file_name}")
        except (OSError, ValueError) as e:
            self._log("ERROR", f"Incremental backup failed: {e}")
            raise

    def optimize_memory(self):
        """Unload all collections to free memory."""
        for collection in list(self.data.keys()):
            self._unload_collection(collection)
        self._log("INFO", "Memory optimized by unloading all collections.")

    def get_stats(self):
        """
        Get database statistics.

        :return: Dictionary with stats (collections, record counts, indexes).
        """
        stats = {
            "collections": len(self.data),
            "records": {},
            "indexes": {}
        }
        for collection in self._get_existing_collections():
            if collection not in self.data or self.data[collection] is None:
                self.data[collection] = self._load_data(collection)
            stats["records"][collection] = len(self.data[collection])
            stats["indexes"][collection] = list(self.indexes.get(collection, {}).keys())
        self._log("INFO", "Generated database statistics")
        return stats
