
# --- Comprehensive Test Suite ---
if __name__ == "__main__":
    def run_tests():
        print("Starting Unosql Test Suite...\n")

        # Initialize database with encryption
        db = Unosql("testdb", encryption_key=b"1234567890abcdef")
        
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

        print("\nAll tests completed successfully!")

    # Run the tests
    run_tests()
