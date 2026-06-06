import socket
import time

host = "aws-0-us-east-2.pooler.supabase.com"
print(f"Resolving {host}...")
start = time.time()
try:
    addr = socket.getaddrinfo(host, 5432)
    end = time.time()
    print(f"Success in {end - start:.2f}s: {addr}")
except Exception as e:
    print(f"Resolution failed: {e}")
