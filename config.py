import os

class Config:
    SECRET_KEY = os.environ.get("thisisforlogginin") or "thisisforlogginin"
    MONGO_URI = os.environ.get("mongodb://localhost:27017/bugtracker") or "mongodb://localhost:27017/bugtracker"

