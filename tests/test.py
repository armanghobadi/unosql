from unosql.core import unosql


def example_usage():
    # Initialize the database with encryption
    db = unosql("my_database", encryption_key=b"16bytekey1234567")

    # Insert records into the "users" collection
    db.insert("users", {"id": 1, "name": "Arman", "age": 29})
    db.insert("users", {"id": 2, "name": "Ayso", "age": 31})
    db.insert("users", {"id": 3, "name": "Aynaz", "age": 19})

    print("All users after insertion:", db.all("users"))

    # Find a specific user by id
    print("Find user with id=2:", db.find("users", "id", 2))

    # Update a user's record
    db.update("users", "id", 2, {"name": "Arman", "age": 30})
    print("All users after update:", db.all("users"))

    # Delete a user
    db.delete("users", "id", 1)
    print("All users after deleting user with id=1:", db.all("users"))

    # Backup the database
    db.backup("backup.db")

    # Clear the collection
    db.clear("users")
    print("All users after clearing:", db.all("users"))

# Run the example
example_usage()

   
