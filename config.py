import os

class Config:
    SECRET_KEY = os.environ.get("thisisforlogginin") or "thisisforlogginin"
    MONGO_URI = os.environ.get("mongodb+srv://bugtrackeruser:bugtrackeruser1234@myatlasclusteredu.fuxls.mongodb.net/?retryWrites=true&w=majority&appName=myAtlasClusterEDU") or "mongodb+srv://bugtrackeruser:bugtrackeruser1234@myatlasclusteredu.fuxls.mongodb.net/?retryWrites=true&w=majority&appName=myAtlasClusterEDU"

