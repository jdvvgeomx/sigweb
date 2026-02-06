from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import sqlite3
import json
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# --- CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = os.environ.get("SECRET_KEY", "uveracruzana_super_secret_key_2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 1 día
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "481357191308-c06t135ahrb8nnk1vq6nfo0bcqn33cdl.apps.googleusercontent.com")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

app = FastAPI(title="Servidor SIG Web Profesional")

# --- BASE DE DATOS ---
DB_PATH = "sig_database.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users') # Recreamos para el nuevo esquema premium
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS points (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT,
            subcategory TEXT,
            description TEXT,
            address TEXT,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            university TEXT,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Admin por defecto
    admin_pass = pwd_context.hash("uv2026")
    cursor.execute('''
        INSERT INTO users (username, password, full_name, email, university, role) 
        VALUES (?, ?, ?, ?, ?, ?)
    ''', ('admin', admin_pass, 'Administrador SIG', 'admin@uv.mx', 'Universidad Veracruzana', 'admin'))
    
    conn.commit()
    conn.close()

init_db()

# --- MODELOS DE DATOS ---
class Point(BaseModel):
    name: str
    category: str
    subcategory: Optional[str] = None
    description: Optional[str] = None
    address: Optional[str] = None
    lat: float
    lng: float

class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    university: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

# --- FUNCIONES DE SEGURIDAD ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales no válidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username # Retorna el username
    except JWTError:
        raise credentials_exception

# --- RUTAS DE LA API - PUNTOS ---

@app.get("/api/v1/points")
async def get_points():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM points')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.post("/api/v1/points")
async def save_point(point: Point, current_user: str = Depends(get_current_user)):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO points (name, category, subcategory, description, address, lat, lng)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (point.name, point.category, point.subcategory, point.description, point.address, point.lat, point.lng))
        conn.commit()
        point_id = cursor.lastrowid
        conn.close()
        return {"status": "success", "id": point_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/points/{point_id}")
async def delete_point(point_id: int, current_user: str = Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM points WHERE id = ?', (point_id,))
    conn.commit()
    conn.close()
    return {"status": "success"}

# --- RUTAS DE AUTENTICACIÓN ---

@app.post("/api/v1/auth/register")
async def register(user: UserCreate):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    hashed_pass = pwd_context.hash(user.password)
    try:
        cursor.execute('''
            INSERT INTO users (username, password, full_name, email, university) 
            VALUES (?, ?, ?, ?, ?)
        ''', (user.username, hashed_pass, user.full_name, user.email, user.university))
        conn.commit()
        return {"status": "success", "message": "Usuario registrado"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    finally:
        conn.close()

@app.post("/api/v1/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (form_data.username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not pwd_context.verify(form_data.password, user['password']):
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    
    # El token llevará el username como sub y el full_name como info extra
    access_token = create_access_token(data={
        "sub": user['username'],
        "name": user['full_name']
    })
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": {
            "username": user['username'],
            "full_name": user['full_name'],
            "university": user['university'],
            "role": user['role']
        }
    }

@app.post("/api/v1/auth/google")
async def google_login(token_data: dict):
    token = token_data.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token de Google ausente")
        
    try:
        # Verificar el token con Google
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        
        # El token es válido, extraemos la info
        email = idinfo['email']
        name = idinfo.get('name', email.split('@')[0])
        picture = idinfo.get('picture')
        
        # Buscar o crear usuario en la BD
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if not user:
            # Si no existe, lo creamos automáticamente
            username = email.split('@')[0]
            # Contraseña aleatoria/inutilizada para usuarios de Google
            dummy_pass = pwd_context.hash(os.urandom(16).hex())
            cursor.execute('''
                INSERT INTO users (username, password, full_name, email, university, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, dummy_pass, name, email, 'Google Account', 'user'))
            conn.commit()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
        
        conn.close()
        
        # Generar nuestro JWT para el sistema
        access_token = create_access_token(data={"sub": user['username'], "name": user['full_name']})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "username": user['username'],
                "full_name": user['full_name'],
                "university": user['university'],
                "role": user['role'],
                "picture": picture
            }
        }
        
    except ValueError:
        raise HTTPException(status_code=400, detail="Token de Google inválido")

# --- RUTAS DE LA API - RUTAS ---

@app.get("/api/v1/rutas")
async def obtener_rutas():
    routes_path = os.path.join("static", "data", "routes")
    files = []
    if os.path.exists(routes_path):
        files = [f for f in os.listdir(routes_path) if f.endswith('.geojson')]
    return {"status": "success", "count": len(files), "files": files}

# Montamos la carpeta static
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
