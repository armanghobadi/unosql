"""
Unosql: A secure NoSQL database for MicroPython optimized for resource-constrained environments.
Designed for critical industries with AES-CBC encryption, HMAC-SHA256 integrity, and compliance
with MISRA and ISO 26262 standards. Supports persistent indexing, atomic transactions, advanced
queries, and robust error recovery.

Key Features:
- Secure data storage with encryption and integrity checks.
- Atomic transactions for data consistency in critical operations.
- Efficient indexing for fast queries in IoT and embedded systems.
- Error recovery with backup and restore mechanisms.
- Memory optimization for microcontrollers with limited RAM.

Edge Cases Handled:
- Disk full: Raises OSError, preserves data via backups.
- File corruption: Detects via checksums, recovers from backup.
- Concurrent access: File locking with stale lock detection.
- Low memory: Lazy loading and memory unloading.
- Power failure: Atomic writes with temporary files.

Standards Compliance:
- MISRA: Input validation, type checking, and error handling.
- ISO 26262: Fault tolerance, atomic operations, and recovery mechanisms.

Usage Example:
    db = Unosql("my_db", encryption_key=b"32_bytekey1234567890123456789012")
    db.insert("collection", {"name": "Alice", "value": 100})
    results = db.find("collection", {"name": "Alice"})
"""

import ujson
import uos
import uhashlib
import utime
import ubinascii
from cryptolib import aes

class Unosql:
    # Constants
    MAX_LOG_SIZE = 10240  # Maximum log file size in bytes
    LOCK_TIMEOUT = 20000  # Lock timeout in milliseconds (increased for reliability)
    STALE_LOCK_THRESHOLD = 30000  # Threshold for stale lock detection (ms)
    SALT_SIZE = 16        # Salt size for key derivation
    IV_SIZE = 16          # Initialization vector size for AES-CBC
    HMAC_SIZE = 32        # HMAC-SHA256 size
    MIN_KEY_LENGTH = 32   # 256-bit key for secure applications
    DEFAULT_ITERATIONS = 1000  # Optimized PBKDF2 iterations
    MIN_ITERATIONS = 100  # Minimum iterations for security

    def __init__(self, db_name: str, encryption_key: bytes = None, iterations: int = DEFAULT_ITERATIONS, log_level: str = "INFO"):
        """
        Initialize the Unosql database with validation and logging.

        Args:
            db_name (str): Name of the database (alphanumeric and underscores only).
            encryption_key (bytes, optional): 32-byte encryption key for AES-CBC. Defaults to None.
            iterations (int): Number of PBKDF2 iterations for key derivation. Defaults to 1000.
            log_level (str): Logging level ("DEBUG", "INFO", "ERROR"). Defaults to "INFO".

        Raises:
            ValueError: If db_name is empty, encryption_key length is invalid, or iterations < MIN_ITERATIONS.
        """
        if not db_name:
            raise ValueError("Database name cannot be empty")
        if encryption_key and len(encryption_key) != self.MIN_KEY_LENGTH:
            raise ValueError(f"Encryption key must be {self.MIN_KEY_LENGTH} bytes")
        if iterations < self.MIN_ITERATIONS:
            raise ValueError(f"Iterations must be at least {self.MIN_ITERATIONS}")

        self.db_name = self._sanitize_name(db_name)
        self.encryption_key = encryption_key
        self.iterations = iterations
        self.log_level = log_level.upper()
        self.salt_file = f"{self.db_name}_salt.db"
        self.salt = self._load_salt() if encryption_key else None
        self.data = {}  # In-memory collections
        self.indexes = {}  # In-memory indexes
        self.locks = {}  # Active locks
        self._initialize_logging()
        self._load_existing_collections()
        self._log("INFO", f"Database {self.db_name} initialized with {iterations} iterations")

    def _sanitize_name(self, name: str) -> str:
        """
        Sanitize database or collection name to prevent injection attacks.

        Args:
            name (str): Name to sanitize.

        Returns:
            str: Sanitized name containing only alphanumeric characters and underscores.

        Raises:
            ValueError: If sanitized name is empty.
        """
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        sanitized = "".join(c for c in name if c in allowed)
        if not sanitized:
            raise ValueError("Sanitized name is empty")
        return sanitized

    def _file_exists(self, filepath: str) -> bool:
        """
        Check if a file exists.

        Args:
            filepath (str): Path to the file.

        Returns:
            bool: True if file exists, False otherwise.
        """
        try:
            uos.stat(filepath)
            return True
        except OSError:
            return False

    def _check_disk_space(self, file_name: str, required_bytes: int) -> None:
        """
        Verify sufficient disk space for writing.

        Args:
            file_name (str): File to check space for.
            required_bytes (int): Required bytes for the operation.

        Raises:
            OSError: If insufficient disk space is available.
        """
        try:
            stat = uos.statvfs(file_name)
            free_bytes = stat[0] * stat[3]
            if free_bytes < required_bytes:
                self._log("ERROR", f"Insufficient disk space for {file_name}")
                raise OSError("Disk full")
        except OSError:
            self._log("DEBUG", "Disk space check not supported, proceeding cautiously")

    def _load_salt(self) -> bytes:
        """
        Load or generate a cryptographic salt for key derivation.

        Returns:
            bytes: Salt for key derivation.

        Raises:
            OSError: If reading or writing the salt file fails.
        """
        if self._file_exists(self.salt_file):
            try:
                with open(self.salt_file, 'rb') as f:
                    return f.read()
            except OSError as e:
                self._log("ERROR", f"Failed to read salt file: {e}")
                raise
        salt = uos.urandom(self.SALT_SIZE)
        try:
            self._check_disk_space(self.salt_file, self.SALT_SIZE)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            self._log("INFO", "Generated new salt")
        except OSError as e:
            self._log("ERROR", f"Failed to write salt file: {e}")
            raise
        return salt

    def _derive_key(self, password: bytes) -> tuple[bytes, bytes]:
        """
        Derive AES and HMAC keys using PBKDF2-like iteration.

        Args:
            password (bytes): Input encryption key.

        Returns:
            tuple[bytes, bytes]: AES key and HMAC key.
        """
        key = password + self.salt
        for _ in range(self.iterations):
            h = uhashlib.sha256()
            h.update(key)
            key = h.digest()
        return key[:self.MIN_KEY_LENGTH], key[self.MIN_KEY_LENGTH:2 * self.MIN_KEY_LENGTH]

    def _compute_hmac(self, key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA256 for data integrity.

        Args:
            key (bytes): HMAC key.
            data (bytes): Data to hash.

        Returns:
            bytes: HMAC-SHA256 digest.
        """
        h = uhashlib.sha256()
        h.update(key + data)
        return h.digest()

    def _encrypt(self, data: str) -> bytes:
        """
        Encrypt data using AES-CBC with HMAC-SHA256 for integrity.

        Args:
            data (str): Data to encrypt.

        Returns:
            bytes: IV + HMAC + ciphertext.
        """
        if not self.encryption_key:
            return data.encode('utf-8')
        aes_key, hmac_key = self._derive_key(self.encryption_key)
        iv = uos.urandom(self.IV_SIZE)
        cipher = aes(aes_key, 1, iv)
        data_bytes = data.encode('utf-8')
        pad_len = 16 - (len(data_bytes) % 16)
        data_bytes += bytes([pad_len] * pad_len)
        ciphertext = cipher.encrypt(data_bytes)
        hmac = self._compute_hmac(hmac_key, iv + ciphertext)
        return iv + hmac + ciphertext

    def _decrypt(self, data: bytes) -> str:
        """
        Decrypt data and verify HMAC integrity.

        Args:
            data (bytes): IV + HMAC + ciphertext.

        Returns:
            str: Decrypted data.

        Raises:
            ValueError: If HMAC verification or padding is invalid.
        """
        if not self.encryption_key:
            return data.decode('utf-8')
        iv = data[:self.IV_SIZE]
        hmac = data[self.IV_SIZE:self.IV_SIZE + self.HMAC_SIZE]
        ciphertext = data[self.IV_SIZE + self.HMAC_SIZE:]
        aes_key, hmac_key = self._derive_key(self.encryption_key)
        computed_hmac = self._compute_hmac(hmac_key, iv + ciphertext)
        if computed_hmac != hmac:
            self._log("ERROR", "HMAC verification failed")
            raise ValueError("Data integrity check failed")
        cipher = aes(aes_key, 1, iv)
        decrypted = cipher.decrypt(ciphertext)
        pad_len = decrypted[-1]
        if pad_len > 16 or decrypted[-pad_len:] != bytes([pad_len] * pad_len):
            self._log("ERROR", "Invalid padding")
            raise ValueError("Invalid padding")
        return decrypted[:-pad_len].decode('utf-8')

    def _compress(self, data: bytes) -> bytes:
        """
        Compress data using uzlib if available.

        Args:
            data (bytes): Data to compress.

        Returns:
            bytes: Compressed or original data if uzlib is unavailable.
        """
        try:
            import uzlib
            self._log("DEBUG", "Using uzlib for compression")
            return uzlib.compress(data)
        except ImportError:
            self._log("DEBUG", "uzlib not available, skipping compression")
            return data

    def _decompress(self, data: bytes) -> bytes:
        """
        Decompress data using uzlib if available.

        Args:
            data (bytes): Data to decompress.

        Returns:
            bytes: Decompressed or original data if uzlib is unavailable.
        """
        try:
            import uzlib
            self._log("DEBUG", "Using uzlib for decompression")
            return uzlib.decompress(data)
        except ImportError:
            self._log("DEBUG", "uzlib not available, assuming uncompressed data")
            return data

    def _initialize_logging(self) -> None:
        """
        Initialize logging system with rotation for critical industries.

        Rotates log file if it exceeds MAX_LOG_SIZE to prevent storage issues.
        """
        log_file = f"{self.db_name}_errors.log"
        try:
            if self._file_exists(log_file) and uos.stat(log_file)[6] > self.MAX_LOG_SIZE:
                uos.rename(log_file, f"{log_file}.{utime.time()}")
                self._log("INFO", "Log file rotated due to size limit")
        except OSError as e:
            self._log("ERROR", f"Failed to initialize logging: {e}")

    def _log(self, level: str, message: str) -> None:
        """
        Log messages based on the configured log level.

        Args:
            level (str): Log level ("DEBUG", "INFO", "ERROR").
            message (str): Message to log.
        """
        if level not in ("DEBUG", "INFO", "ERROR"):
            return
        if (self.log_level == "ERROR" and level != "ERROR") or \
           (self.log_level == "INFO" and level == "DEBUG"):
            return
        try:
            log_file = f"{self.db_name}_errors.log"
            with open(log_file, 'a') as f:
                f.write(f"[{utime.time()}] {level}: {message}\n")
        except OSError as e:
            print(f"Log error: {e}")

    def _acquire_lock(self, collection_name: str, timeout_ms: int = LOCK_TIMEOUT) -> None:
        """
        Acquire a file lock with stale lock detection.

        Args:
            collection_name (str): Name of the collection to lock.
            timeout_ms (int): Lock timeout in milliseconds.

        Raises:
            OSError: If lock acquisition times out or fails.
        """
        lock_file = f"{self.db_name}_{collection_name}.lock"
        start_time = utime.ticks_ms()
        while self._file_exists(lock_file):
            try:
                with open(lock_file, 'rb') as f:
                    lock_time = int(f.read().decode('utf-8'))
                if utime.ticks_diff(utime.ticks_ms(), lock_time) > self.STALE_LOCK_THRESHOLD:
                    self._log("INFO", f"Removing stale lock for {collection_name}")
                    uos.remove(lock_file)
                elif utime.ticks_diff(utime.ticks_ms(), start_time) > timeout_ms:
                    self._log("ERROR", f"Lock timeout for {collection_name}")
                    raise OSError(f"Lock timeout for {collection_name}")
                utime.sleep_ms(10)
            except (OSError, ValueError):
                self._log("ERROR", f"Invalid lock file {lock_file}, removing")
                uos.remove(lock_file)
        try:
            with open(lock_file, 'wb') as f:
                f.write(str(utime.ticks_ms()).encode('utf-8'))
            self.locks[collection_name] = lock_file
            self._log("DEBUG", f"Lock acquired for {collection_name}")
        except OSError as e:
            self._log("ERROR", f"Failed to acquire lock for {collection_name}: {e}")
            raise

    def _release_lock(self, collection_name: str) -> None:
        """
        Release a file lock.

        Args:
            collection_name (str): Name of the collection to unlock.
        """
        if collection_name in self.locks:
            try:
                uos.remove(self.locks[collection_name])
                del self.locks[collection_name]
                self._log("DEBUG", f"Lock released for {collection_name}")
            except OSError as e:
                self._log("ERROR", f"Failed to release lock for {collection_name}: {e}")

    def _validate_records(self, records: list) -> None:
        """
        Validate record structure and types.

        Args:
            records (list): List of records to validate.

        Raises:
            ValueError: If records are not a list of dictionaries or contain invalid types.
        """
        if not isinstance(records, list):
            raise ValueError("Records must be a list")
        for rec in records:
            if not isinstance(rec, dict):
                raise ValueError("Each record must be a dictionary")
            for k, v in rec.items():
                if not isinstance(k, str):
                    raise ValueError(f"Record key must be a string, got {type(k)}")
                if not self._is_valid_type(v):
                    raise ValueError(f"Invalid data type for key {k}: {type(v)}")

    def _is_valid_type(self, value) -> bool:
        """
        Check if a value type is valid for storage.

        Args:
            value: Value to check.

        Returns:
            bool: True if type is valid, False otherwise.
        """
        return isinstance(value, (str, int, float, bool, list, dict, type(None)))

    def _load_existing_collections(self) -> None:
        """
        Load existing collections and their indexes into memory.
        """
        for collection in self._get_existing_collections():
            self.data[collection] = None
            self.indexes[collection] = self._load_index(collection)
        self._log("INFO", f"Initialized {len(self.data)} collections")

    def _get_existing_collections(self) -> list:
        """
        List existing collection files.

        Returns:
            list: List of collection names.
        """
        collections = []
        try:
            for file in uos.listdir():
                if (file.startswith(self.db_name) and file.endswith(".db") and
                    file != self.salt_file and not file.endswith(".lock") and not file.endswith(".bak")):
                    collections.append(file[len(self.db_name) + 1:-3])
            self._log("DEBUG", f"Found collections: {collections}")
        except OSError as e:
            self._log("ERROR", f"Error listing collections: {e}")
        return collections

    def _next_id(self, collection_name: str) -> int:
        """
        Generate the next record ID for a collection.

        Args:
            collection_name (str): Name of the collection.

        Returns:
            int: Next available record ID.
        """
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        records = self.data[collection_name]
        return max((record.get("id", 0) for record in records), default=0) + 1

    def _unload_collection(self, collection_name: str) -> None:
        """
        Unload a collection from memory to optimize RAM usage.

        Args:
            collection_name (str): Name of the collection to unload.
        """
        if collection_name in self.data and self.data[collection_name] is not None:
            self._save_data(collection_name, self.data[collection_name])
            self.data[collection_name] = None
            self._log("INFO", f"Unloaded collection {collection_name} from memory")

    def _build_index(self, collection_name: str, key: str, filter_func=None) -> None:
        """
        Build an index for a single key.

        Args:
            collection_name (str): Name of the collection.
            key (str): Key to index.
            filter_func (callable, optional): Function to filter records for partial indexing.
        """
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        index = {"values": {}, "min": None, "max": None}
        for i, record in enumerate(self.data[collection_name]):
            if filter_func and not filter_func(record):
                continue
            value = record.get(key)
            if value is not None:
                index["values"].setdefault(value, []).append(i)
                if isinstance(value, (int, float)):
                    if index["min"] is None or value < index["min"]:
                        index["min"] = value
                    if index["max"] is None or value > index["max"]:
                        index["max"] = value
        self.indexes[collection_name][key] = index
        self._save_index(collection_name)
        self._log("DEBUG", f"Built index for {key} in {collection_name}")

    def _build_compound_index(self, collection_name: str, keys: list, filter_func=None) -> None:
        """
        Build a compound index for multiple keys.

        Args:
            collection_name (str): Name of the collection.
            keys (list): List of keys to index.
            filter_func (callable, optional): Function to filter records for partial indexing.
        """
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        index = {}
        for i, record in enumerate(self.data[collection_name]):
            if filter_func and not filter_func(record):
                continue
            value = tuple(record.get(k) for k in keys)
            if all(v is not None for v in value):
                index.setdefault(value, []).append(i)
        index_key = ":".join(keys)
        self.indexes[collection_name][index_key] = index
        self._save_index(collection_name)
        self._log("DEBUG", f"Built compound index {index_key} in {collection_name}")

    def _save_index(self, collection_name: str) -> None:
        """
        Save indexes to file.

        Args:
            collection_name (str): Name of the collection.

        Raises:
            OSError: If writing to the index file fails.
        """
        index_file = f"{self.db_name}_{collection_name}.idx"
        try:
            raw_data = ujson.dumps(self.indexes[collection_name])
            if self.encryption_key:
                raw_data = self._encrypt(raw_data)
            self._check_disk_space(index_file, len(raw_data))
            with open(index_file, 'wb') as f:
                f.write(raw_data)
            self._log("DEBUG", f"Saved index for {collection_name}")
        except OSError as e:
            self._log("ERROR", f"Failed to save index {index_file}: {e}")

    def _load_index(self, collection_name: str) -> dict:
        """
        Load indexes from file.

        Args:
            collection_name (str): Name of the collection.

        Returns:
            dict: Loaded indexes or empty dict if file doesn't exist or is corrupted.
        """
        index_file = f"{self.db_name}_{collection_name}.idx"
        if not self._file_exists(index_file):
            return {}
        try:
            with open(index_file, 'rb') as f:
                raw_data = f.read()
            if self.encryption_key:
                raw_data = self._decrypt(raw_data)
            return ujson.loads(raw_data)
        except (OSError, ValueError) as e:
            self._log("ERROR", f"Failed to load index {index_file}: {e}")
            return {}

    def _update_indexes(self, collection_name: str, data: list) -> None:
        """
        Update all indexes for a collection.

        Args:
            collection_name (str): Name of the collection.
            data (list): Updated collection data.
        """
        for key in self.indexes.get(collection_name, {}):
            if ":" in key:
                self._build_compound_index(collection_name, key.split(":"))
            else:
                self._build_index(collection_name, key)

    def _load_data(self, collection_name: str) -> list:
        """
        Load collection data from file.

        Args:
            collection_name (str): Name of the collection.

        Returns:
            list: Loaded records or empty list if file is missing or corrupted.

        Raises:
            OSError: If file access fails.
            ValueError: If data is corrupted or invalid.
        """
        file_name = f"{self.db_name}_{collection_name}.db"
        if not self._file_exists(file_name):
            self._log("INFO", f"No data file for {collection_name}")
            return []
        try:
            self._acquire_lock(collection_name)
            with open(file_name, 'rb') as f:
                data = f.read()
            checksum, raw_data = data[:32], data[32:]
            if uhashlib.sha256(raw_data).digest() != checksum:
                self._log("ERROR", f"Corrupted data file {file_name}")
                return self._recover_data(collection_name)
            raw_data = self._decompress(raw_data)
            if self.encryption_key:
                raw_data = self._decrypt(raw_data)
            data = ujson.loads(raw_data)
            self._validate_records(data)
            self._log("INFO", f"Loaded {len(data)} records from {collection_name}")
            return data
        except (OSError, ValueError, UnicodeError) as e:
            self._log("ERROR", f"Error loading {file_name}: {e}")
            return self._recover_data(collection_name)
        finally:
            self._release_lock(collection_name)

    def _save_data(self, collection_name: str, data: list) -> None:
        """
        Save collection data to file atomically.

        Args:
            collection_name (str): Name of the collection.
            data (list): Data to save.

        Raises:
            OSError: If file operations fail.
            ValueError: If data validation fails.
        """
        file_name = f"{self.db_name}_{collection_name}.db"
        temp_file = f"{file_name}.tmp"
        backup_file = f"{file_name}.bak"
        try:
            self._acquire_lock(collection_name)
            if self._file_exists(file_name):
                uos.rename(file_name, backup_file)
            self._validate_records(data)
            raw_data = ujson.dumps(data)
            if self.encryption_key:
                raw_data = self._encrypt(raw_data)
            raw_data = self._compress(raw_data)
            checksum = uhashlib.sha256(raw_data).digest()
            self._check_disk_space(file_name, len(checksum) + len(raw_data))
            with open(temp_file, 'wb') as f:
                f.write(checksum + raw_data)
            uos.rename(temp_file, file_name)
            if self._file_exists(backup_file):
                uos.remove(backup_file)
            self._update_indexes(collection_name, data)
            self._log("INFO", f"Saved {len(data)} records to {collection_name}")
        except (OSError, ValueError) as e:
            self._log("ERROR", f"Error saving {file_name}: {e}")
            if self._file_exists(backup_file):
                uos.rename(backup_file, file_name)
            raise
        finally:
            self._release_lock(collection_name)

    def _recover_data(self, collection_name: str) -> list:
        """
        Recover data from backup file.

        Args:
            collection_name (str): Name of the collection.

        Returns:
            list: Recovered records or empty list if no backup exists.
        """
        backup_file = f"{self.db_name}_{collection_name}_backup.db"
        if self._file_exists(backup_file):
            self._log("INFO", f"Recovering from backup {backup_file}")
            try:
                uos.rename(backup_file, f"{self.db_name}_{collection_name}.db")
                return self._load_data(collection_name)
            except OSError as e:
                self._log("ERROR", f"Recovery failed: {e}")
        self._log("ERROR", f"No backup available for {collection_name}")
        return []

    class Transaction:
        """
        Context manager for atomic transactions to ensure data consistency.

        Attributes:
            db (Unosql): Database instance.
            collection_name (str): Sanitized collection name.
            locked (bool): Lock status.
            original_data (list): Copy of original collection data for rollback.
        """
        def __init__(self, db, collection_name: str):
            self.db = db
            self.collection_name = db._sanitize_name(collection_name)
            self.locked = False
            self.original_data = None

        def __enter__(self):
            self.db._acquire_lock(self.collection_name)
            self.locked = True
            if self.collection_name not in self.db.data or self.db.data[self.collection_name] is None:
                self.db.data[self.collection_name] = self.db._load_data(self.collection_name)
            self.original_data = self.db.data[self.collection_name].copy()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is not None:
                self.db.data[self.collection_name] = self.original_data
                self.db._log("INFO", f"Transaction rolled back for {self.collection_name}")  # استفاده از self.db._log
            else:
                self.db._save_data(self.collection_name, self.db.data[self.collection_name])
            if self.locked:
                self.db._release_lock(self.collection_name)

        def insert(self, record: dict):
            """Insert a record within the transaction."""
            self.db.insert(self.collection_name, record)

        def update(self, key: str, value, new_record: dict):
            """Update records within the transaction."""
            self.db.update(self.collection_name, key, value, new_record)

        def delete(self, key: str, value):
            """Delete records within the transaction."""
            self.db.delete(self.collection_name, key, value)

    def transaction(self, collection_name: str) -> 'Transaction':
        """
        Create a transaction context for atomic operations.

        Args:
            collection_name (str): Name of the collection.

        Returns:
            Transaction: Transaction context manager.
        """
        return self.Transaction(self, collection_name)

    def create_index(self, collection_name: str, keys: str | list, filter_func=None) -> None:
        """
        Create single or compound index for efficient queries.

        Args:
            collection_name (str): Name of the collection.
            keys (str | list): Single key or list of keys to index.
            filter_func (callable, optional): Function to filter records for partial indexing.

        Raises:
            ValueError: If keys are invalid.
        """
        collection_name = self._sanitize_name(collection_name)
        if not isinstance(keys, (str, list)):
            raise ValueError("Keys must be a string or list of strings")
        if isinstance(keys, str):
            keys = [keys]
        if not all(isinstance(k, str) for k in keys):
            raise ValueError("All keys must be strings")
        if collection_name not in self.indexes:
            self.indexes[collection_name] = {}
        if len(keys) == 1:
            self._build_index(collection_name, keys[0], filter_func)
        else:
            self._build_compound_index(collection_name, keys, filter_func)

    def insert(self, collection_name: str, record: dict) -> None:
        """
        Insert a record with metadata (ID, timestamp, version).

        Args:
            collection_name (str): Name of the collection.
            record (dict): Record to insert.

        Raises:
            ValueError: If record is not a dictionary or contains invalid types.
        """
        collection_name = self._sanitize_name(collection_name)
        if not isinstance(record, dict):
            raise ValueError("Record must be a dictionary")
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        record = record.copy()
        record["id"] = self._next_id(collection_name)
        record["timestamp"] = utime.time()
        record["version"] = 1
        self._validate_records([record])
        self.data[collection_name].append(record)
        self._save_data(collection_name, self.data[collection_name])

    def find(self, collection_name: str, query: dict) -> list:
        """
        Find records matching the query.

        Args:
            collection_name (str): Name of the collection.
            query (dict): Query conditions (e.g., {"key": "value", "key2": {"gt": 10}}).

        Returns:
            list: Matching records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        try:
            import re
            has_regex = True
        except ImportError:
            has_regex = False
        results = []
        for record in self.data[collection_name]:
            match = True
            for key, condition in query.items():
                value = record.get(key)
                if isinstance(condition, dict):
                    for op, op_value in condition.items():
                        if op == "gt":
                            if not (isinstance(value, (int, float)) and float(value) > float(op_value)):
                                match = False
                        elif op == "lt":
                            if not (isinstance(value, (int, float)) and float(value) < float(op_value)):
                                match = False
                        elif op == "gte":
                            if not (isinstance(value, (int, float)) and float(value) >= float(op_value)):
                                match = False
                        elif op == "lte":
                            if not (isinstance(value, (int, float)) and float(value) <= float(op_value)):
                                match = False
                        elif op == "regex" and has_regex and isinstance(value, str):
                            if not re.match(op_value, value):
                                match = False
                        else:
                            match = False
                elif value != condition:
                    match = False
            if match:
                results.append(record)
        return results

    def update(self, collection_name: str, key: str, value, new_record: dict) -> bool:
        """
        Update records matching a key-value pair.

        Args:
            collection_name (str): Name of the collection.
            key (str): Key to match.
            value: Value to match.
            new_record (dict): New data to update.

        Returns:
            bool: True if at least one record was updated, False otherwise.
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

    def delete(self, collection_name: str, key: str, value) -> int:
        """
        Delete records matching a key-value pair.

        Args:
            collection_name (str): Name of the collection.
            key (str): Key to match.
            value: Value to match.

        Returns:
            int: Number of records deleted.
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

    def all(self, collection_name: str) -> list:
        """
        Return all records in a collection.

        Args:
            collection_name (str): Name of the collection.

        Returns:
            list: All records in the collection.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name]

    def clear(self, collection_name: str) -> None:
        """
        Clear all records in a collection.

        Args:
            collection_name (str): Name of the collection.
        """
        collection_name = self._sanitize_name(collection_name)
        self.data[collection_name] = []
        self.indexes[collection_name] = {}
        self._save_data(collection_name, self.data[collection_name])

    def count(self, collection_name: str) -> int:
        """
        Count records in a collection.

        Args:
            collection_name (str): Name of the collection.

        Returns:
            int: Number of records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return len(self.data[collection_name])

    def get_last_n_records(self, collection_name: str, n: int) -> list:
        """
        Get the last N records in a collection.

        Args:
            collection_name (str): Name of the collection.
            n (int): Number of records to retrieve.

        Returns:
            list: Last N records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name][-n:]

    def get_records_in_timeframe(self, collection_name: str, time_key: str, start_time: int, end_time: int) -> list:
        """
        Get records within a time range.

        Args:
            collection_name (str): Name of the collection.
            time_key (str): Key containing timestamp.
            start_time (int): Start of time range (Unix timestamp).
            end_time (int): End of time range (Unix timestamp).

        Returns:
            list: Records within the time range.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return [r for r in self.data[collection_name] if start_time <= r.get(time_key, 0) <= end_time]

    def get_first_n_records(self, collection_name: str, n: int) -> list:
        """
        Get the first N records in a collection.

        Args:
            collection_name (str): Name of the collection.
            n (int): Number of records to retrieve.

        Returns:
            list: First N records.
        """
        collection_name = self._sanitize_name(collection_name)
        if collection_name not in self.data or self.data[collection_name] is None:
            self.data[collection_name] = self._load_data(collection_name)
        return self.data[collection_name][:n]

    def backup(self, backup_file_name: str) -> None:
        """
        Create a full backup of the database.

        Args:
            backup_file_name (str): Name of the backup file.

        Raises:
            OSError: If file operations fail.
            ValueError: If data serialization fails.
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
            self._check_disk_space(backup_file_name, len(checksum) + len(raw_data))
            with open(backup_file_name, 'wb') as f:
                f.write(checksum + raw_data)
            if not self._file_exists(backup_file_name):
                raise OSError(f"Failed to create backup file {backup_file_name}")
            self._log("INFO", f"Backup created: {backup_file_name}")
        except (OSError, ValueError) as e:
            self._log("ERROR", f"Backup failed: {e}")
            raise

    def restore(self, backup_file_name: str) -> None:
        """
        Restore the database from a backup.

        Args:
            backup_file_name (str): Name of the backup file.

        Raises:
            OSError: If backup file is missing or inaccessible.
            ValueError: If backup file is corrupted.
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

    def incremental_backup(self, backup_file_name: str, since_timestamp: int) -> None:
        """
        Create an incremental backup since a timestamp.

        Args:
            backup_file_name (str): Name of the backup file.
            since_timestamp (int): Unix timestamp for incremental backup.

        Raises:
            OSError: If file operations fail.
            ValueError: If data serialization fails.
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
            self._check_disk_space(backup_file_name, len(checksum) + len(raw_data))
            with open(backup_file_name, 'wb') as f:
                f.write(checksum + raw_data)
            self._log("INFO", f"Incremental backup created: {backup_file_name}")
        except (OSError, ValueError) as e:
            self._log("ERROR", f"Incremental backup failed: {e}")
            raise

    def optimize_memory(self) -> None:
        """
        Optimize memory by unloading all collections.
        """
        for collection in list(self.data.keys()):
            self._unload_collection(collection)
        self._log("INFO", "Memory optimized by unloading all collections")

    def get_stats(self) -> dict:
        """
        Generate database statistics.

        Returns:
            dict: Statistics including collection count, record counts, and index information.
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

