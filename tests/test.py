import uos
import utime
from unosql.core import Unosql

class UnosqlTestSuite:
    """Test suite for Unosql database functionality."""
    
    def __init__(self):
        """Initialize test suite with database instance."""
        self.db_name = "testdb"
        self.encryption_key = b"1234567890abcdef"  # 16-byte key for AES-CBC
        self.db = Unosql(self.db_name, encryption_key=self.encryption_key, log_level="DEBUG")
        self.collection = "users"
        self._cleanup()

    def _cleanup(self):
        """Remove existing test files to ensure clean state."""
        try:
            for file in uos.listdir():
                if file.startswith(self.db_name) or file.endswith("_backup"):
                    uos.remove(file)
        except OSError:
            pass

    def test_1_insert(self):
        """Test inserting records."""
        records = [
            {"name": "Alice", "age": 25},
            {"name": "Bob", "age": 30},
            {"name": "Charlie", "age": 35}
        ]
        for rec in records:
            self.db.insert(self.collection, rec)
        count = self.db.count(self.collection)
        print(f"Inserted {count} records, count: {count} - {'PASS' if count == 3 else 'FAIL'}")
        return count == 3

    def test_2_find_with_index(self):
        """Test finding records with index."""
        self.db.create_index(self.collection, "name")
        result = self.db.find(self.collection, "name", "Alice")
        expected = {"name": "Alice", "age": 25}
        passed = len(result) == 1 and all(k in result[0] and result[0][k] == v for k, v in expected.items())
        print(f"Found Alice: {result} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_3_update_with_versioning(self):
        """Test updating records with versioning."""
        self.db.update(self.collection, "name", "Alice", {"age": 26})
        result = self.db.find(self.collection, "name", "Alice")
        passed = len(result) == 1 and result[0]["age"] == 26 and result[0]["version"] == 2
        print(f"Updated Alice's age to 26, version: 2: {result[0]} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_4_delete(self):
        """Test deleting records."""
        deleted = self.db.delete(self.collection, "name", "Bob")
        count = self.db.count(self.collection)
        print(f"Deleted Bob, remaining count: {count} - {'PASS' if deleted == 1 and count == 2 else 'FAIL'}")
        return deleted == 1 and count == 2

    def test_5_get_all(self):
        """Test retrieving all records."""
        records = self.db.all(self.collection)
        expected_names = {"Alice", "Charlie"}
        passed = len(records) == 2 and all(r["name"] in expected_names for r in records)
        print(f"All users: {records} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_6_get_last_n(self):
        """Test retrieving last n records."""
        result = self.db.get_last_n_records(self.collection, 1)
        passed = len(result) == 1 and result[0]["name"] == "Charlie"
        print(f"Last record: {result} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_7_get_in_timeframe(self):
        """Test retrieving records in a timeframe."""
        now = utime.time()
        result = self.db.get_records_in_timeframe(self.collection, "timestamp", now - 1000, now + 1000)
        passed = len(result) == 2 and all(r["name"] in ["Alice", "Charlie"] for r in result)
        print(f"Records in timeframe: {result} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_8_clear_collection(self):
        """Test clearing a collection."""
        self.db.clear(self.collection)
        count = self.db.count(self.collection)
        print(f"Cleared users, count: {count} - {'PASS' if count == 0 else 'FAIL'}")
        return count == 0

    def test_9_backup_restore(self):
        """Test backup and restore with integrity check."""
        # Insert test data
        records = [
            {"name": "Dave", "age": 40},
            {"name": "Eve", "age": 45}
        ]
        for rec in records:
            self.db.insert(self.collection, rec)
        
        # Create backup
        backup_file = "testdb_backup"
        self.db.backup(backup_file)
        backup_exists = uos.stat(backup_file)[6] > 0
        
        # Clear database
        self.db.clear(self.collection)
        cleared_count = self.db.count(self.collection)
        
        # Restore from backup
        self.db.restore(backup_file)
        restored_records = self.db.all(self.collection)
        passed = (backup_exists and cleared_count == 0 and 
                  len(restored_records) == 2 and 
                  all(r["name"] in ["Dave", "Eve"] for r in restored_records))
        print(f"Backup and restore: {restored_records} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_10_compound_index(self):
        """Test compound indexing."""
        self.db.clear(self.collection)
        records = [
            {"name": "Frank", "city": "NY", "age": 28},
            {"name": "Grace", "city": "NY", "age": 32},
            {"name": "Henry", "city": "LA", "age": 28}
        ]
        for rec in records:
            self.db.insert(self.collection, rec)
        self.db.create_index(self.collection, ["city", "age"])
        result = self.db.find(self.collection, ["city", "age"], ["NY", 28])
        passed = len(result) == 1 and result[0]["name"] == "Frank"
        print(f"Compound index search: {result} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_11_incremental_backup(self):
        """Test incremental backup."""
        self.db.clear(self.collection)
        records = [
            {"name": "Ivy", "age": 50},
            {"name": "Jack", "age": 55}
        ]
        for rec in records:
            self.db.insert(self.collection, rec)
        timestamp = utime.time() - 100
        backup_file = "testdb_inc_backup"
        self.db.incremental_backup(backup_file, timestamp)
        backup_exists = uos.stat(backup_file)[6] > 0
        self.db.clear(self.collection)
        self.db.restore(backup_file)
        restored = self.db.all(self.collection)
        passed = backup_exists and len(restored) == 2 and all(r["name"] in ["Ivy", "Jack"] for r in restored)
        print(f"Incremental backup: {restored} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_12_lock_timeout(self):
        """Test lock timeout handling."""
        lock_file = f"{self.db_name}_{self.collection}.lock"
        try:
            with open(lock_file, 'wb') as f:
                f.write(b'locked')
            try:
                self.db._acquire_lock(self.collection, timeout_ms=100)
                passed = False
            except OSError:
                passed = True
            print(f"Lock timeout: {'PASS' if passed else 'FAIL'}")
            return passed
        finally:
            try:
                uos.remove(lock_file)
            except OSError:
                pass

    def test_13_data_validation(self):
        """Test data type validation."""
        try:
            self.db.insert(self.collection, {1: "Invalid", "data": "test"})  # Invalid key type (integer)
            passed = False
        except ValueError as e:
            passed = str(e).startswith("Record key must be a string")
        print(f"Data validation: {'PASS' if passed else 'FAIL'}")
        return passed

    def test_14_memory_optimization(self):
        """Test memory optimization by unloading collections."""
        self.db.clear(self.collection)
        self.db.insert(self.collection, {"name": "Kate", "age": 60})
        self.db.optimize_memory()
        self.db.insert(self.collection, {"name": "Liam", "age": 65})
        count = self.db.count(self.collection)
        passed = count == 1  # Only Liam should remain after unload and new insert
        print(f"Memory optimization: count={count} - {'PASS' if passed else 'FAIL'}")
        return passed

    def test_15_stats(self):
        """Test database statistics."""
        self.db.clear(self.collection)
        self.db.insert(self.collection, {"name": "Mia", "age": 70})
        self.db.create_index(self.collection, "name")
        stats = self.db.get_stats()
        passed = (stats["collections"] == 1 and 
                  stats["records"][self.collection] == 1 and 
                  stats["indexes"][self.collection] == ["name"])
        print(f"Stats: {stats} - {'PASS' if passed else 'FAIL'}")
        return passed

    def run_tests(self):
        """Run all tests and report results."""
        print("Starting Unosql Test Suite...\n")
        tests = [
            self.test_1_insert,
            self.test_2_find_with_index,
            self.test_3_update_with_versioning,
            self.test_4_delete,
            self.test_5_get_all,
            self.test_6_get_last_n,
            self.test_7_get_in_timeframe,
            self.test_8_clear_collection,
            self.test_9_backup_restore,
            self.test_10_compound_index,
            self.test_11_incremental_backup,
            self.test_12_lock_timeout,
            self.test_13_data_validation,
            self.test_14_memory_optimization,
            self.test_15_stats
        ]
        passed = 0
        for i, test in enumerate(tests, 1):
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"Test {i} failed with error: {e}")
        print(f"\nTest Summary: {passed}/{len(tests)} tests passed")
        return passed == len(tests)

if __name__ == "__main__":
    suite = UnosqlTestSuite()
    suite.run_tests()
