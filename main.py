from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import psycopg2
from psycopg2 import extras
import json
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi.middleware.gzip import GZipMiddleware
from fastapi import File, UploadFile
import uuid
import shutil

# --- CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = os.environ.get("SECRET_KEY", "uveracruzana_super_secret_key_2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 1 día
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "481357191308-c06t135ahrb8nnk1vq6nfo0bcqn33cdl.apps.googleusercontent.com")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SIG Web")
app.add_middleware(GZipMiddleware, minimum_size=1000)

# --- CONFIGURACIÓN DE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Permite cualquier origen (GitHub Pages, localhost, etc.)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CARPETA DE UPLOADS ---
UPLOAD_DIR = "static/uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# --- BASE DE DATOS (SUPABASE) ---
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:Tekunikaru1997+@db.lpulqvzzhqynjlxaxgoq.supabase.co:5432/postgres")

def get_db_conn():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=extras.RealDictCursor)
    return conn

def init_db():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS points (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT,
            subcategory TEXT,
            description TEXT,
            address TEXT,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            image_url TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Intentar agregar columnas si la tabla ya existía sin ellas
    try:
        cursor.execute('ALTER TABLE points ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP')
    except:
        pass # Ya existe o error al agregar
        
    # Columna likes si no existe
    try:
        cursor.execute('ALTER TABLE points ADD COLUMN likes INTEGER DEFAULT 0')
    except:
        pass

    # Columnas de auditoría si no existen
    try:
        cursor.execute('ALTER TABLE points ADD COLUMN created_by TEXT')
        cursor.execute('ALTER TABLE points ADD COLUMN created_by_name TEXT')
    except:
        pass

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            point_id INTEGER,
            user_name TEXT,
            content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (point_id) REFERENCES points(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            university TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Admin por defecto
    admin_pass = pwd_context.hash("uv2026")
    cursor.execute('''
        INSERT INTO users (username, password, full_name, email, university, role) 
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    ''', ('admin', admin_pass, 'Administrador SIG', 'admin@uv.mx', 'Universidad Veracruzana', 'admin'))
    
    conn.commit()
    cursor.close()
    conn.close()

init_db()

# --- MODELOS DE DATOS ---
class Point(BaseModel):
    name: str = Field(..., max_length=100)
    category: str
    subcategory: Optional[str] = None
    description: Optional[str] = Field(None, max_length=500)
    address: Optional[str] = None
    lat: float
    lng: float
    image_url: Optional[str] = None
    likes: Optional[int] = 0

class CommentCreate(BaseModel):
    content: str = Field(..., max_length=300)

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
            
        # Buscar usuario en BD para obtener su rol actualizado
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user is None:
            raise credentials_exception
            
        return dict(user) 
    except JWTError:
        raise credentials_exception

# --- RUTAS DE LA API - PUNTOS ---

@app.get("/api/v1/points")
async def get_points():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM points')
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [dict(row) for row in rows]

# --- NUEVOS ENDPOINTS SOCIALES ---

@app.post("/api/v1/points/{point_id}/like")
async def like_point(point_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('UPDATE points SET likes = likes + 1 WHERE id = %s', (point_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success"}

@app.post("/api/v1/points/{point_id}/comments")
async def add_comment(point_id: int, comment: CommentCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO comments (point_id, user_name, content) 
        VALUES (%s, %s, %s)
    ''', (point_id, current_user['full_name'], comment.content))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success"}

@app.get("/api/v1/points/{point_id}/comments")
async def get_comments(point_id: int):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM comments WHERE point_id = %s ORDER BY timestamp DESC', (point_id,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [dict(row) for row in rows]

@app.post("/api/v1/upload")
async def upload_image(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    # Generar nombre único para evitar colisiones
    ext = file.filename.split(".")[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    return {"url": f"/uploads/{filename}"}

@app.post("/api/v1/points")
async def save_point(point: Point, current_user: dict = Depends(get_current_user)):
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO points (name, category, subcategory, description, address, lat, lng, image_url, created_by, created_by_name)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (point.name, point.category, point.subcategory, point.description, point.address, point.lat, point.lng, point.image_url, current_user['username'], current_user['full_name']))
        conn.commit()
        point_id = cursor.fetchone()['id']
        cursor.close()
        conn.close()
        return {"status": "success", "id": point_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- ENDPOINT DE ESTADÍSTICAS / INFORMES ---

@app.get("/api/v1/admin/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado")
        
    conn = get_db_conn()
    cursor = conn.cursor()
    
    # Agrupar por usuario y fecha (solo el día)
    query = '''
        SELECT 
            created_by_name as usuario,
            timestamp::date as fecha,
            COUNT(*) as total_puntos,
            STRING_AGG(name, ', ') as nombres_puntos
        FROM points 
        GROUP BY created_by_name, created_by, timestamp::date
        ORDER BY fecha DESC, usuario ASC
    '''
    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [dict(row) for row in rows]

@app.delete("/api/v1/points/{point_id}")
async def delete_point(point_id: int, current_user: dict = Depends(get_current_user)):
    # Solo el admin puede borrar
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="No tienes permisos para eliminar puntos. Solo el administrador puede realizar esta acción.")
        
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM points WHERE id = %s', (point_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"status": "success"}

# --- RUTAS DE AUTENTICACIÓN ---

def is_uv_email(email: str) -> bool:
    email = email.lower().strip()
    return email.endswith("@uv.mx") or email.endswith("@estudiantes.uv.mx")

@app.post("/api/v1/auth/register")
async def register(user: UserCreate):
    if not is_uv_email(user.email):
        raise HTTPException(
            status_code=400, 
            detail="Solo se permiten correos institucionales de la UV (@uv.mx o @estudiantes.uv.mx)"
        )
    conn = get_db_conn()
    cursor = conn.cursor()
    hashed_pass = pwd_context.hash(user.password)
    try:
        cursor.execute('''
            INSERT INTO users (username, password, full_name, email, university) 
            VALUES (%s, %s, %s, %s, %s)
        ''', (user.username, hashed_pass, user.full_name, user.email, user.university))
        conn.commit()
        return {"status": "success", "message": "Usuario registrado"}
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/v1/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = %s', (form_data.username,))
    user = cursor.fetchone()
    cursor.close()
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

        if not is_uv_email(email):
            raise HTTPException(
                status_code=403, 
                detail="Acceso denegado: Tu cuenta de Google no pertenece a la Universidad Veracruzana"
            )

        name = idinfo.get('name', email.split('@')[0])
        picture = idinfo.get('picture')
        
        # Buscar o crear usuario en la BD
        conn = get_db_conn()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if not user:
            # Si no existe, lo creamos automáticamente
            username = email.split('@')[0]
            # Contraseña aleatoria/inutilizada para usuarios de Google
            dummy_pass = pwd_context.hash(os.urandom(16).hex())
            cursor.execute('''
                INSERT INTO users (username, password, full_name, email, university, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (username, dummy_pass, name, email, 'Google Account', 'user'))
            conn.commit()
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
        
        cursor.close()
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
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
