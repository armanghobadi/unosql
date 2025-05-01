# unosql - A Lightweight Encrypted NoSQL Database for MicroPython

![unosql Logo](./tests/logo.png) 



`unosql` is a lightweight, serverless NoSQL database designed for the MicroPython environment. It provides secure data storage with AES-CBC encryption, optional `uzlib` compression, and advanced features like compound indexing, record versioning, concurrency control, and full/incremental backups. Optimized for resource-constrained devices like ESP32 and ESP8266, `unosql` is ideal for IoT and embedded applications requiring robust data management.

## Table of Contents

- [Features](#features)
- [Install in MicroPython Environment](#install-in-micropython-environment)
- [Usage](#usage)
- [Example Usage](#example-usage)
- [Requirements](#requirements)
- [Test Suite](#test-suite)
- [Performance Considerations](#performance-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

| Feature | Description |
|---------|-------------|
| **NoSQL Database** | Stores data in JSON format for flexible collection management. |
| **AES-CBC Encryption** | Secures data with AES-CBC encryption and HMAC-SHA256 integrity checks using a 16-byte key. |
| **Optional Compression** | Supports `uzlib` compression to reduce storage size, with fallback to uncompressed storage. |
| **Collection-Based Storage** | Organizes data into separate collections for modular data management. |
| **Advanced CRUD Operations** | Supports insert, find, update, delete, and retrieve all records with versioning and timestamps. |
| **Compound Indexing** | Enables single-key and multi-key indexing for efficient searches. |
| **Record Versioning** | Tracks changes with version numbers and timestamps for auditability. |
| **Concurrency Control** | Implements file-based locking with configurable timeouts for thread-safe operations. |
| **Full & Incremental Backups** | Provides backup and restore with checksum verification for data integrity. |
| **Memory Optimization** | Unloads collections to free memory on low-resource devices. |
| **Robust Logging** | Configurable logging (DEBUG, INFO, ERROR) with log rotation for debugging. |
| **Secure Key Derivation** | Uses PBKDF2-like derivation with SHA256 and salt for enhanced security. |
| **Serverless Design** | Ideal for IoT and embedded systems on MicroPython-compatible boards. |

## Install in MicroPython Environment

Ensure you're using MicroPython (version 1.21 or later recommended). Download it from [micropython.org](https://micropython.org) if not already installed.

To install `unosql`, manually copy the `unosql.py` file to your MicroPython device using a tool like `ampy`, `rshell`, or WebREPL, as it is not yet available via `upip`:

```bash
ampy --port /dev/ttyUSB0 put unosql.py
```

Then import the library:

```python
from unosql.core import Unosql
```

No additional dependencies are required beyond MicroPython’s built-in modules (`ujson`, `uos`, `uhashlib`, `utime`, `ubinascii`, `cryptolib`). Optional `uzlib` compression requires a MicroPython build with `MICROPY_PY_UZLIB` enabled.

## Usage

### 1. Creating a Database

To create a new database, instantiate the `Unosql` class with the database name. Optionally, provide a 16-byte encryption key, key derivation iterations, and log level.

```python
db = Unosql("my_database", encryption_key=b"16bytekey1234567", iterations=10000, log_level="DEBUG")
```

### 2. Inserting Records

Use the `insert` method to add a new record (a dictionary) to a collection. Records automatically receive an `id`, `timestamp`, and `version`.

```python
db.insert("users", {"name": "Arman", "age": 29})
```

### 3. Finding Records

To find records matching a key-value pair or compound keys, use the `find` method. Create indexes for faster searches.

```python
db.find("users", "name", "Arman")
```

### 4. Updating Records

To update records based on a key-value match, use the `update` method. Updates increment the version and timestamp.

```python
db.update("users", "name", "Arman", {"age": 30})
```

### 5. Deleting Records

To delete records matching a key-value pair, use the `delete` method.

```python
db.delete("users", "name", "Arman")
```

### 6. Reading All Records

Use the `all` method to retrieve all records in a collection.

```python
db.all("users")
```

### 7. Clearing a Collection

To clear all records and indexes from a collection, use the `clear` method.

```python
db.clear("users")
```

### 8. Backup and Restore

You can back up the entire database or incrementally to a file, or restore it from a backup:

```python
# Backup the database
db.backup("backup.db")

# Incremental backup
db.incremental_backup("inc_backup.db", since_timestamp=utime.time() - 3600)

# Restore the database from a backup
db.restore("backup.db")
```

## Example Usage

Here’s a simple example demonstrating how to use `unosql`:

```python
import utime
from unosql.core import Unosql

# --- Comprehensive Test Suite ---
if __name__ == "__main__":
    def run_tests():
        print("Starting Unosql Test Suite...\n")

        # Initialize database with encryption
        db = Unosql("testdb", encryption_key=b"1234567890abcdef", log_level="DEBUG")

        # Test 1: Insert records
        print("Test 1: Inserting records")
        db.insert("users", {"name": "Alice", "age": 25})
        db.insert("users", {"name": "Bob", "age": 30})
        db.insert("users", {"name": "Charlie", "age": 35})
        assert db.count("users") == 3, "Insert failed: wrong count"
        print(f"Inserted 3 records, count: {db.count('users')} - PASS")

        # Test 2: Find records
        print("\nTest 2: Finding records")
        alice_records = db.find("users", "name", "Alice")
        assert len(alice_records) == 1 and alice_records[0]["age"] == 25, "Find failed"
        print(f"Found Alice: {alice_records} - PASS")

        # Test 3: Update records
        print("\nTest 3: Updating records")
        updated = db.update("users", "name", "Alice", {"age": 26})
        assert updated and db.find("users", "name", "Alice")[0]["age"] == 26, "Update failed"
        print(f"Updated Alice's age to 26: {db.find('users', 'name', 'Alice')} - PASS")

        # Test 4: Delete records
        print("\nTest 4: Deleting records")
        deleted_count = db.delete("users", "name", "Bob")
        assert deleted_count == 1 and db.count("users") == 2, "Delete failed"
        print(f"Deleted Bob, remaining count: {db.count('users')} - PASS")

        # Test 5: Get all records
        print("\nTest 5: Getting all records")
        all_users = db.all("users")
        assert len(all_users) == 2, "All records fetch failed"
        print(f"All users: {all_users} - PASS")

        # Test 6: Get last N records
        print("\nTest 6: Getting last 1 record")
        last_record = db.get_last_n_records("users", 1)
        assert len(last_record) == 1 and last_record[0]["name"] == "Charlie", "Last N failed"
        print(f"Last record: {last_record} - PASS")

        # Test 7: Get records in timeframe
        print("\nTest 7: Getting records in timeframe")
        start_time = utime.time() - 10  # Within last 10 seconds
        end_time = utime.time() + 10
        recent_records = db.get_records_in_timeframe("users", "timestamp", start_time, end_time)
        assert len(recent_records) == 2, "Timeframe filter failed"
        print(f"Records in timeframe: {recent_records} - PASS")

        # Test 8: Clear collection
        print("\nTest 8: Clearing collection")
        db.clear("users")
        assert db.count("users") == 0, "Clear failed"
        print(f"Cleared users, count: {db.count('users')} - PASS")

        # Test 9: Backup and restore
        print("\nTest 9: Backup and restore")
        db.insert("users", {"name": "David", "age": 40})
        db.insert("users", {"name": "Eve", "age": 28})
        db.backup("testdb_backup.db")
        db.clear("users")
        assert db.count("users") == 0, "Pre-restore count failed"
        db.restore("testdb_backup.db")
        assert db.count("users") == 2, "Restore failed"
        print(f"Restored users: {db.all('users')} - PASS")

        # Test 10: Error handling - Invalid record
        print("\nTest 10: Error handling - Invalid record")
        try:
            db.insert("users", "not_a_dict")
            print("Insert with invalid record should have failed - FAIL")
        except ValueError:
            print("Caught invalid record error - PASS")

        # Test 11: Error handling - Restore non-existent file
        print("\nTest 11: Error handling - Restore non-existent file")
        try:
            db.restore("non_existent_file.db")
            print("Restore with non-existent file should have failed - FAIL")
        except OSError:
            print("Caught non-existent file error - PASS")

        # Test 12: Multiple collections
        print("\nTest 12: Multiple collections")
        db.insert("products", {"name": "Laptop", "price": 1000})
        db.insert("products", {"name": "Phone", "price": 500})
        assert db.count("products") == 2 and db.count("users") == 2, "Multiple collections failed"
        print(f"Users: {db.count('users')}, Products: {db.count('products')} - PASS")

        # Test 13: Compound indexing
        print("\nTest 13: Compound indexing")
        db.clear("users")
        db.insert("users", {"name": "Frank", "city": "NY", "age": 28})
        db.insert("users", {"name": "Grace", "city": "NY", "age": 32})
        db.create_index("users", ["city", "age"])
        result = db.find("users", ["city", "age"], ["NY", 28])
        assert len(result) == 1 and result[0]["name"] == "Frank", "Compound index failed"
        print(f"Compound index search: {result} - PASS")

        # Test 14: Incremental backup
        print("\nTest 14: Incremental backup")
        db.clear("users")
        db.insert("users", {"name": "Ivy", "age": 50})
        db.insert("users", {"name": "Jack", "age": 55})
        timestamp = utime.time() - 100
        db.incremental_backup("testdb_inc_backup.db", timestamp)
        db.clear("users")
        db.restore("testdb_inc_backup.db")
        restored = db.all("users")
        assert len(restored) == 2 and all(r["name"] in ["Ivy", "Jack"] for r in restored), "Incremental backup failed"
        print(f"Incremental backup: {restored} - PASS")

        # Test 15: Memory optimization
        print("\nTest 15: Memory optimization")
        db.clear("users")
        db.insert("users", {"name": "Kate", "age": 60})
        db.optimize_memory()
        db.insert("users", {"name": "Liam", "age": 65})
        assert db.count("users") == 1, "Memory optimization failed"
        print(f"Memory optimization, count: {db.count('users')} - PASS")

        print("\nAll tests completed successfully!")

    # Run the tests
    run_tests()
```

## Requirements

- **MicroPython**: This library is designed for use with MicroPython on ESP32, ESP8266, or other compatible boards. Version 1.21+ recommended for optional `uzlib` compression.
- **Built-in Modules**: Requires `ujson`, `uos`, `uhashlib`, `utime`, `ubinascii`, `cryptolib` (included in most MicroPython builds).
- **Optional**: `uzlib` for compression (requires a MicroPython build with `MICROPY_PY_UZLIB` enabled).
- **Storage**: Sufficient flash storage for database files (e.g., `testdb_users.db`, `testdb_backup.db`) and logs (`testdb_errors.log`).

## Test Suite

The `unosql` library includes a comprehensive test suite (`tests.py`) that verifies all functionality, including CRUD operations, compound indexing, backups, concurrency, data validation, and memory optimization. To run the tests, copy `unosql.py` and `tests.py` to your device and execute

Logs are saved to `testdb_errors.log` for debugging. Expected output includes 15 passing tests, as shown in the [Example Usage](#example-usage).

## Test Images

![unosql in Test-file](./tests/test.png)


## Performance Considerations

- **Storage**: Without `uzlib`, database files are stored uncompressed, increasing storage needs. Enable `uzlib` for better efficiency.
- **Memory**: Use `optimize_memory` on low-RAM devices (e.g., ESP8266) to unload collections.
- **Concurrency**: Adjust `LOCK_TIMEOUT` (default: 5000ms) for high-concurrency applications.
- **Encryption**: Higher `iterations` for key derivation (default: 10000) enhances security but may slow initialization on low-power devices.


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

