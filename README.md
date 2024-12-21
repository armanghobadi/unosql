
# unosql - A Lightweight Encrypted NoSQL Database for MicroPython

`unosql` is a lightweight, serverless NoSQL database designed for the MicroPython environment. It supports AES encryption for secure data storage and enables CRUD (Create, Read, Update, Delete, Backup) operations on collections stored in JSON format.

## Features

- **NoSQL Database**: Stores data in JSON format, allowing easy collection management.
- **AES Encryption**: Provides AES encryption (ECB mode) to secure your data using a 16-byte encryption key.
- **Collection-Based Storage**: Allows data to be stored and retrieved in separate collections.
- **CRUD Operations**: Supports adding, searching, updating, deleting, and reading all records.
- **Key-Value Pair Searching**: Efficiently find and filter data based on key-value pairs.
- **Secure Key Generation**: Generates encryption keys securely using HMAC and SHA256.
- **Serverless**: Perfect for use in embedded systems like ESP32, ESP8266, or other MicroPython-compatible boards.


### Install in MicroPython Environment

Ensure you're using the MicroPython environment. If you haven't installed MicroPython yet, download it from the official site.

To install `unosql` in your MicroPython environment, use the `upip` package manager:

```bash
upip install unosql
```

Then import the library:

```python
from unosql import unosql
```

No additional dependencies are required.

## Usage

### 1. Creating a Database

To create a new database, instantiate the `unosql` class with the database name. Optionally, you can provide an encryption key (16 bytes) for data encryption.

```python
db = unosql("my_database", encryption_key=b"16bytekey1234567")
```

### 2. Inserting Records

Use the `insert` method to add a new record (a dictionary) to a collection:

```python
db.insert("users", {"id": 1, "name": "Arman", "age": 29})
```

### 3. Finding Records

To find records that match a key-value pair, use the `find` method:

```python
db.find("users", "id", 1)
```

### 4. Updating Records

To update records based on a key-value match, use the `update` method:

```python
db.update("users", "id", 1, {"name": "Arman", "age": 30})
```

### 5. Deleting Records

To delete records that match a key-value pair, use the `delete` method:

```python
db.delete("users", "id", 1)
```

### 6. Reading All Records

Use the `all` method to retrieve all records in a collection:

```python
db.all("users")
```

### 7. Clearing a Collection

To clear all records from a collection, use the `clear` method:

```python
db.clear("users")
```

### 8. Backup and Restore

You can back up the entire database to a file or restore it from a backup:

```python
# Backup the database
db.backup("backup.db")

# Restore the database from a backup
db.restore("backup.db")
```

## Example Usage

Here’s a simple example demonstrating how to use `unosql`:

```python
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
```

## Requirements

- **MicroPython**: This library is designed for use with MicroPython on ESP32, ESP8266, or other compatible boards.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Test Images

![unosql in Test-file](./tests/test.png)
