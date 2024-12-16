from unosql.core import unosql




def example_usage():
    # Initialize the database with encryption
    db = unosql("my_database", encryption_key=b"16bytekey1234567")
    
    # Inserting records into a collection named "users"
    print("Inserting records...")
    db.insert("users", {"id": 1, "name": "Arman", "age": 29})
    db.insert("users", {"id": 2, "name": "Ayso", "age": 31})
    db.insert("users", {"id": 3, "name": "Aynaz", "age": 19})

    # Retrieve all records in the "users" collection
    all_users = db.all("users")
    print("All users after insertion:", all_users)

    # Find a specific user by id
    print("\nFinding user with id=2...")
    user = db.find("users", "id", 2)
    print("Found user with id=2:", user)

    # Update a user record
    print("\nUpdating user with id=2...")
    updated = db.update("users", "id", 2, {"name": "Ayso", "age": 32})
    print(f"Update successful: {updated}")

    # Retrieve all records in the "users" collection after the update
    all_users_updated = db.all("users")
    print("All users after update:", all_users_updated)

    # Delete a user by id
    print("\nDeleting user with id=1...")
    deleted_count = db.delete("users", "id", 1)
    print(f"Number of records deleted with id=1: {deleted_count}")

    # Retrieve all records in the "users" collection after deletion
    all_users_after_deletion = db.all("users")
    print("All users after deletion of id=1:", all_users_after_deletion)

    # Clear the "users" collection
    print("\nClearing the 'users' collection...")
    db.clear("users")
    all_users_cleared = db.all("users")
    print("All users after clearing the collection:", all_users_cleared)

    # Example with no data in collection (edge case)
    print("\nTrying to retrieve data from an empty collection 'empty_users'...")
    empty_users = db.all("empty_users")
    print("All users in 'empty_users' collection:", empty_users)

    # Example with encryption handling (to check if encrypted data is saved and retrieved correctly)
    print("\nInserting encrypted records into 'encrypted_users' collection...")
    db.insert("encrypted_users", {"id": 1, "name": "EncryptedArman", "age": 30})
    db.insert("encrypted_users", {"id": 2, "name": "EncryptedAyso", "age": 32})

    # Retrieve encrypted data
    encrypted_users = db.all("encrypted_users")
    print("All users in 'encrypted_users' collection:", encrypted_users)

    # Edge case for update when no records match
    print("\nUpdating non-existent user with id=999...")
    updated_nonexistent = db.update("users", "id", 999, {"name": "NonExistent", "age": 99})
    print(f"Update successful for non-existent user: {updated_nonexistent}")

    # Edge case for delete when no records match
    print("\nDeleting non-existent user with id=999...")
    deleted_nonexistent = db.delete("users", "id", 999)
    print(f"Number of records deleted for non-existent id=999: {deleted_nonexistent}")

# Run the example
example_usage()
