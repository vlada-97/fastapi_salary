import os
from datetime import datetime, timedelta

import jwt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext

import db

app = FastAPI(title='Salary')

SECRET_KEY = os.getenv("SECRET_KEY", "secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    return user


def authenticate_user(username, password, conn):
    user = get_user(username, conn)
    if user is None:
        return False
    stored_password = user[2]
    if not verify_password(password, stored_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


security = HTTPBasic()


def authenticate_token(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password = credentials.password
    conn = db.create_connection()
    user = authenticate_user(username, password, conn)
    conn.close()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user[1]


@app.post("/token")
def login_for_access_token(credentials: HTTPBasicCredentials = Depends(security)):
    username, password = credentials.username, credentials.password
    conn = db.create_connection()
    user = authenticate_user(username, password, conn)
    conn.close()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user[1]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/salary")
def get_salary(username: str = Depends(authenticate_token)):
    conn = db.create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    salary = cursor.fetchone()
    conn.close()
    if salary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Salary not found for the user",
        )
    return {"username": username, "salary": salary[3]}


if __name__ == "__main__":
    conn = db.create_connection()
    db.create_table_users(conn)
    db.insert_sample_data_users(conn)
    conn.close()
    uvicorn.run(app, host="127.0.0.1", port=8000)
