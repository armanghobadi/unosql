### Test Suite
"""
Test suite for Unosql database, ensuring functionality and reliability for critical industries.
Covers initialization, sanitization, encryption, data operations, indexing, transactions,
error recovery, backup/restore, and memory optimization.
"""

import uos
import utime
from unosql import Unosql

# Fixed encryption key for all tests
ENCRYPTION_KEY = b"32_bytekey1234567890123456789012"

def cleanup_files(db_name: str) -> None:
    """
    Remove all files related to the test database, including locks, backups, and logs.

    Args:
        db_name (str): Name of the database.
    """
    try:
        for file in uos.listdir():
            if (
                file.startswith(db_name) or
                file.endswith(".lock") or
                file in ["test_backup.db", "test_incremental.db"]
            ):
                try:
                    uos.remove(file)
                except OSError as e:
                    print(f"Warning: Cannot remove file {file}: {e}")
    except OSError as e:
        print(f"Warning: Cannot list directory contents: {e}")

def test_initialization():
    """Test database initialization and input validation."""
    print("\nTest Initialization")
    db_name = "test_db"
    
    try:
        db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, iterations=100, log_level="ERROR")
        if db.db_name == db_name and uos.stat(db.salt_file):
            print("PASS: Valid initialization")
        else:
            print("FAIL: Valid initialization failed")
    except Exception as e:
        print(f"FAIL: Valid initialization error: {e}")
    
    try:
        Unosql(db_name, encryption_key=b"shortkey")
        print("FAIL: Invalid key length not caught")
    except ValueError:
        print("PASS: Invalid key length caught")
    
    try:
        Unosql(db_name, encryption_key=ENCRYPTION_KEY, iterations=50)
        print("FAIL: Invalid iterations not caught")
    except ValueError:
        print("PASS: Invalid iterations caught")
    
    try:
        Unosql("", encryption_key=ENCRYPTION_KEY)
        print("FAIL: Empty db name not caught")
    except ValueError:
        print("PASS: Empty db name caught")
    
    cleanup_files(db_name)

def test_sanitize_name():
    """Test sanitization of database and collection names."""
    print("\nTest Sanitize Name")
    db_name = "test_db"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    if db._sanitize_name("valid_name123") == "valid_name123":
        print("PASS: Valid name sanitized correctly")
    else:
        print("FAIL: Valid name sanitization failed")
    
    if db._sanitize_name("invalid#name!") == "invalidname":
        print("PASS: Invalid name sanitized correctly")
    else:
        print("FAIL: Invalid name sanitization failed")
    
    try:
        db._sanitize_name("!@#$%")
        print("FAIL: Invalid name not caught")
    except ValueError:
        print("PASS: Invalid name caught")
    
    cleanup_files(db_name)

def test_encryption_decryption():
    """Test AES-CBC encryption and HMAC-SHA256 integrity."""
    print("\nTest Encryption/Decryption")
    db_name = "test_db"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    data = "Test secure data"
    try:
        encrypted = db._encrypt(data)
        decrypted = db._decrypt(encrypted)
        if decrypted == data:
            print("PASS: Encryption/decryption successful")
        else:
            print("FAIL: Decryption mismatch")
    except Exception as e:
        print(f"FAIL: Encryption/decryption error: {e}")
    
    try:
        invalid_encrypted = encrypted[:-32] + b'\x00' * 32
        db._decrypt(invalid_encrypted)
        print("FAIL: Invalid HMAC not caught")
    except ValueError:
        print("PASS: Invalid HMAC caught")
    
    cleanup_files(db_name)

def test_insert_and_find():
    """Test record insertion and retrieval."""
    print("\nTest Insert and Find")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    record = {"name": "Alice", "age": 30}
    try:
        db.insert(collection, record)
        results = db.find(collection, {"name": "Alice"})
        if (len(results) == 1 and results[0]["name"] == "Alice" and
            results[0]["age"] == 30 and "id" in results[0] and
            "timestamp" in results[0] and results[0]["version"] == 1):
            print("PASS: Insert and find successful")
        else:
            print("FAIL: Insert or find mismatch")
    except Exception as e:
        print(f"FAIL: Insert/find error: {e}")
    
    cleanup_files(db_name)

def test_update():
    """Test updating records with versioning."""
    print("\nTest Update")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Bob", "age": 25})
        updated = db.update(collection, "name", "Bob", {"age": 26})
        results = db.find(collection, {"name": "Bob"})
        if (updated and len(results) == 1 and results[0]["age"] == 26 and
            results[0]["version"] == 2):
            print("PASS: Update successful")
        else:
            print("FAIL: Update mismatch")
    except Exception as e:
        print(f"FAIL: Update error: {e}")
    
    cleanup_files(db_name)

def test_delete():
    """Test deleting records."""
    print("\nTest Delete")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Charlie", "age": 40})
        deleted = db.delete(collection, "name", "Charlie")
        results = db.find(collection, {"name": "Charlie"})
        if deleted == 1 and len(results) == 0:
            print("PASS: Delete successful")
        else:
            print("FAIL: Delete mismatch")
    except Exception as e:
        print(f"FAIL: Delete error: {e}")
    
    cleanup_files(db_name)

def test_indexing():
    """Test single, compound, and partial indexing."""
    print("\nTest Indexing")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Dave", "age": 35})
        db.insert(collection, {"name": "Eve", "age": 35})
        
        db.create_index(collection, "age")
        results = db.find(collection, {"age": 35})
        if len(results) == 2:
            print("PASS: Single index query successful")
        else:
            print("FAIL: Single index query failed")
        
        db.create_index(collection, ["name", "age"])
        results = db.find(collection, {"name": "Dave", "age": 35})
        if len(results) == 1:
            print("PASS: Compound index query successful")
        else:
            print("FAIL: Compound index query failed")
        
        db.create_index(collection, "age", filter_func=lambda r: r.get("age", 0) > 30)
        results = db.find(collection, {"age": 35})
        if len(results) == 2:
            print("PASS: Partial index query successful")
        else:
            print("FAIL: Partial index query failed")
    except Exception as e:
        print(f"FAIL: Indexing error: {e}")
    
    cleanup_files(db_name)

def test_advanced_queries():
    """Test range and regex queries."""
    print("\nTest Advanced Queries")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Alice", "age": 30})
        db.insert(collection, {"name": "Bob", "age": 40})
        
        results = db.find(collection, {"age": {"gt": 35}})
        print(f"DEBUG: Range query results: {[r['name'] for r in results]}, count: {len(results)}")
        if len(results) == 1 and results[0]["name"] == "Bob":
            print("PASS: Range query successful")
        else:
            print("FAIL: Range query failed")
        
        try:
            import re
            results = db.find(collection, {"name": {"regex": "^A.*"}})
            if len(results) == 1 and results[0]["name"] == "Alice":
                print("PASS: Regex query successful")
            else:
                print("FAIL: Regex query failed")
        except ImportError:
            print("SKIP: Regex query (re module not available)")
    except Exception as e:
        print(f"FAIL: Advanced queries error: {e}")
    
    cleanup_files(db_name)

def test_transactions():
    """Test atomic transactions with lock handling."""
    print("\nTest Transactions")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    cleanup_files(db_name)
    
    try:
        with db.transaction(collection) as tx:
            tx.insert({"name": "Frank", "age": 50})
            tx.update("name", "Frank", {"age": 51})
        results = db.find(collection, {"name": "Frank"})
        if len(results) == 1 and results[0]["age"] == 51:
            print("PASS: Transaction commit successful")
        else:
            print("FAIL: Transaction commit failed")
        
        try:
            with db.transaction(collection) as tx:
                tx.insert({"name": "Grace", "age": 60})
                raise ValueError("Simulated error")
        except ValueError:
            results = db.find(collection, {"name": "Grace"})
            if len(results) == 0:
                print("PASS: Transaction rollback successful")
            else:
                print("FAIL: Transaction rollback failed")
    except Exception as e:
        print(f"FAIL: Transaction error: {e}")
    
    cleanup_files(db_name)

def test_error_recovery():
    """Test recovery from corrupted data."""
    print("\nTest Error Recovery")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Helen", "age": 45})
        db.backup(f"{db_name}_{collection}_backup.db")
        file_name = f"{db_name}_{collection}.db"
        with open(file_name, 'wb') as f:
            f.write(b"corrupted_data")
        results = db.all(collection)
        if len(results) == 1 and results[0]["name"] == "Helen":
            print("PASS: Error recovery successful")
        else:
            print("FAIL: Error recovery failed")
    except Exception as e:
        print(f"FAIL: Error recovery error: {e}")
    
    cleanup_files(db_name)

def test_backup_restore():
    """Test full and incremental backup/restore."""
    print("\nTest Backup and Restore")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Ivy", "age": 28})
        backup_file = "test_backup.db"
        db.backup(backup_file)
        db.clear(collection)
        db.restore(backup_file)
        results = db.find(collection, {"name": "Ivy"})
        if len(results) == 1 and results[0]["age"] == 28:
            print("PASS: Full backup/restore successful")
        else:
            print("FAIL: Full backup/restore failed")
        
        db.insert(collection, {"name": "Jack", "age": 29, "timestamp": utime.time()})
        db.incremental_backup("test_incremental.db", utime.time() - 100)
        db.clear(collection)
        db.restore("test_incremental.db")
        results = db.find(collection, {"name": "Jack"})
        if len(results) == 1 and results[0]["age"] == 29:
            print("PASS: Incremental backup successful")
        else:
            print("FAIL: Incremental backup failed")
    except Exception as e:
        print(f"FAIL: Backup/restore error: {e}")
    
    cleanup_files(db_name)

def test_disk_full():
    """Test handling of disk full condition."""
    print("\nTest Disk Full")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    original_check = db._check_disk_space
    def mock_check_disk_space(file_name, required_bytes):
        raise OSError("Disk full")
    db._check_disk_space = mock_check_disk_space
    
    try:
        db.insert(collection, {"name": "Kate", "age": 33})
        print("FAIL: Disk full not caught")
    except OSError:
        print("PASS: Disk full caught")
    
    db._check_disk_space = original_check
    cleanup_files(db_name)

def test_concurrent_access():
    """Test handling of concurrent access via locks."""
    print("\nTest Concurrent Access")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    lock_file = f"{db_name}_{collection}.lock"
    try:
        with open(lock_file, 'wb') as f:
            f.write(str(utime.ticks_ms() - Unosql.STALE_LOCK_THRESHOLD - 1000).encode('utf-8'))
        db._acquire_lock(collection)
        print("PASS: Stale lock removed and acquired")
    except OSError:
        print("FAIL: Stale lock handling failed")
    finally:
        try:
            uos.remove(lock_file)
        except OSError:
            pass
    
    cleanup_files(db_name)

def test_memory_optimization():
    """Test memory optimization by unloading collections."""
    print("\nTest Memory Optimization")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Leo", "age": 27})
        db.optimize_memory()
        results = db.find(collection, {"name": "Leo"})
        if len(results) == 1 and results[0]["age"] == 27:
            print("PASS: Memory optimization and reload successful")
        else:
            print("FAIL: Memory optimization failed")
    except Exception as e:
        print(f"FAIL: Memory optimization error: {e}")
    
    cleanup_files(db_name)

def test_stats():
    """Test database statistics generation."""
    print("\nTest Stats")
    db_name = "test_db"
    collection = "test_collection"
    db = Unosql(db_name, encryption_key=ENCRYPTION_KEY, log_level="ERROR")
    
    try:
        db.insert(collection, {"name": "Mia", "age": 32})
        stats = db.get_stats()
        if (stats["collections"] == 1 and
            stats["records"][collection] == 1 and
            stats["indexes"][collection] == []):
            print("PASS: Stats successful")
        else:
            print("FAIL: Stats mismatch")
    except Exception as e:
        print(f"FAIL: Stats error: {e}")
    
    cleanup_files(db_name)

# Run all tests
if __name__ == "__main__":
    print("Running Unosql Tests")
    test_initialization()
    test_sanitize_name()
    test_encryption_decryption()
    test_insert_and_find()
    test_update()
    test_delete()
    test_indexing()
    test_advanced_queries()
    test_transactions()
    test_error_recovery()
    test_backup_restore()
    test_disk_full()
    test_concurrent_access()
    test_memory_optimization()
    test_stats()

