
# unosql - A Lightweight NoSQL Database for MicroPython

`unosql` is a lightweight and fast NoSQL database for the MicroPython environment that supports AES encryption and allows data to be stored in JSON files. This library provides CRUD (Create, Read, Update, Delete) operations with optional encryption support.

## Features

- **NoSQL Database**: Uses JSON format for data storage.
- **AES Encryption Support**: Enables encryption and decryption of data using AES in ECB mode.
- **Collection Support**: Allows data to be stored and retrieved in separate collections.
- **CRUD Operations**: Supports adding, searching, updating, deleting, and reading all records.
- **Key-Value Pair Searching**: Find and filter data based on key-value pairs.
- **HMAC-Based Security**: Generates secure encryption keys using HMAC and SHA256.
- **Serverless Database**: Suitable for use in embedded systems and MicroPython environments.

## Installation

### Install in MicroPython Environment

1. Make sure you're using the MicroPython environment. If you haven't installed MicroPython yet, you can download it from the [official MicroPython site](https://micropython.org/download/).

2. To install **unosql**, you can use `upip`:

 for MicroPython, use the appropriate package manager like `upip` to install directly on your microcontroller.

```bash
upip install unosql
```

```python
from unosql.core import unosql
```

No additional libraries are required.

## Usage

### 1. Creating a Database

To create a database, instantiate the `unosql` class with the name of the database file. Optionally, you can provide an encryption key to enable encryption.

```python
db = unosql("my_database", encryption_key=b"16bytekey1234567")
```

### 2. Inserting Records

To insert a record into a collection, use the `insert` method.

```python
db.insert("users", {"id": 1, "name": "Arman", "age": 29})
```

### 3. Finding Records

To find records based on a key-value pair, use the `find` method.

```python
db.find("users", "id", 1)
```

### 4. Updating Records

To update records that match a key-value pair, use the `update` method.

```python
db.update("users", "id", 1, {"name": "Arman", "age": 30})
```

### 5. Deleting Records

To delete records matching a key-value pair, use the `delete` method.

```python
db.delete("users", "id", 1)
```

### 6. Reading All Records

To read all records from a collection, use the `all` method.

```python
db.all("users")
```

### 7. Clearing a Collection

To clear all records from a collection, use the `clear` method.

```python
db.clear("users")
```

## Example Usage

Here is a simple example of using `unosql`:

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

    # Clear the collection
    db.clear("users")
    print("All users after clearing:", db.all("users"))

# Run the example
example_usage()
```
## Requirements
- **MicroPython**: This library is designed for use with MicroPython on ESP32, ESP8266, or other compatible boards.

## License
This project is licensed under the MIT License - see the LICENSE file for details.


## Test Images


![unosql in Test-file](./tests/test.png)



