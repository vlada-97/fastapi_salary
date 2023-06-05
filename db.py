import sqlite3
from sqlite3 import Error
from passlib.hash import bcrypt


def create_connection():
    conn = None
    try:
        conn = sqlite3.connect("users.db")
        print("Connected to SQLite database")
        return conn
    except Error as e:
        print(e)

    return conn


def create_table_users(conn):
    sql = '''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        salary INTEGER DEFAULT 0
    );
    '''
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        conn.commit()
        print("Users table created successfully")
    except Error as e:
        print(e)


def insert_sample_data_users(conn):
    sql = '''
    INSERT INTO users (username, password, salary) VALUES
        ('username1', ?, 5000),
        ('username2', ?, 6000),
        ('username3', ?, 7000);
    '''
    try:
        cursor = conn.cursor()
        hashed_passwords = [
            bcrypt.hash("password1"),
            bcrypt.hash("password2"),
            bcrypt.hash("password3")
        ]
        cursor.execute(sql, hashed_passwords)
        conn.commit()
        print("Sample data inserted into users table successfully")
    except Error as e:
        print(e)


def main():
    conn = create_connection()

    if conn is not None:
        create_table_users(conn)
        insert_sample_data_users(conn)
        conn.close()
    else:
        print("Error connecting to the database")


if __name__ == "__main__":
    main()
