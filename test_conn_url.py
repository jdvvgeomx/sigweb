import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
db_url = os.environ.get('DATABASE_URL')
# Add sslmode if not present in url for test
if "?" not in db_url:
    db_url += "?sslmode=require"

print(f"Trying to connect to: {db_url}")

try:
    conn = psycopg2.connect(db_url, connect_timeout=5)
    print("Success!")
    conn.close()
except Exception as e:
    print(f"Error: {e}")
