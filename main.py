from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Form
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
import ssl
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi.middleware.gzip import GZipMiddleware
# Importaciones de FastAPI consolidadas arriba
import uuid
import shutil
import boto3
from botocore.exceptions import NoCredentialsError
from dotenv import load_dotenv

# Cargar variables desde .env (en local)
load_dotenv()

# --- CONFIGURACIÓN DE SEGURIDAD ---
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    import secrets
    # Generamos una llave aleatoria si no existe una definida en el entorno
    SECRET_KEY = secrets.token_hex(32)
    print("AVISO: Usando SECRET_KEY aleatoria (No persistente).")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 1 día
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID") 

# --- CONFIGURACIÓN DE S3 (STORAGE) ---
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME")
AWS_REGION = os.environ.get("AWS_S3_REGION", "us-east-1")
# Endpoint opcional para servicios S3-compatibles (Supabase, Backblaze, etc.)
AWS_ENDPOINT_URL = os.environ.get("AWS_S3_ENDPOINT_URL")

s3_client = None
if AWS_ACCESS_KEY and AWS_SECRET_KEY:
    try:
        from botocore.client import Config
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY.strip(),
            aws_secret_access_key=AWS_SECRET_KEY.strip(),
            region_name=AWS_REGION,
            endpoint_url=AWS_ENDPOINT_URL,
            config=Config(signature_version='s3v4')
        )
        print(f"S3 Storage configurado: {AWS_BUCKET_NAME}")
    except Exception as e:
        print(f"Error inicializando S3: {e}")
        s3_client = None
else:
    print("S3 no configurado. Usando almacenamiento local.")

# --- CONFIGURACIÓN DE CORREO (SMTP) ---
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", 465)) # Cambiado a 465 por defecto para SSL
SMTP_USER = os.environ.get("SMTP_USER", "adminofizeus@gmail.com").strip()
SMTP_PASS = os.environ.get("SMTP_PASSWORD", "").strip() 
ADMIN_NOTIFY_EMAIL = os.environ.get("ADMIN_NOTIFY_EMAIL", "adminofizeus@gmail.com").strip()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SIG Web")
app.add_middleware(GZipMiddleware, minimum_size=1000)

# --- CONFIGURACIÓN DE CORS ---
# Agrega aquí tus dominios específicos cuando los tengas
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5500",
    "https://sig-web-uv.onrender.com",
    # Reemplaza con tu URL real de GitHub Pages si es diferente
    "https://jdvvgeomx.github.io" 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CARPETA DE UPLOADS ---
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# --- BASE DE DATOS (SUPABASE) ---
# Usamos urllib.parse para manejar caracteres especiales en la contraseña
import urllib.parse

# La URL se obtiene de las variables de entorno para mayor seguridad
DATABASE_URL_ENV = os.environ.get("DATABASE_URL")

from contextlib import contextmanager

@contextmanager
def get_db_conn():
    if not DATABASE_URL_ENV:
        print("ERROR: La variable DATABASE_URL no está configurada en Render.")
        yield None
        return
    
    db_url = DATABASE_URL_ENV.strip().replace('"', '').replace("'", "")
    conn = None
    try:
        conn = psycopg2.connect(
            db_url, 
            cursor_factory=extras.RealDictCursor, 
            sslmode='require',
            connect_timeout=5
        )
        yield conn
    except Exception as e:
        print(f"Error crítico conectando a la base de datos: {e}")
        yield None
    finally:
        if conn:
            conn.close()

def init_db():
    with get_db_conn() as conn:
        if not conn:
            print("AVISO: No se pudo conectar a la base de datos. El sistema funcionará en modo degradado.")
            return
        
        try:
            cursor = conn.cursor()
            # Tabla de Puntos
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
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    likes INTEGER DEFAULT 0,
                    created_by TEXT,
                    created_by_name TEXT
                )
            ''')
            
            # ... resto de tablas (simplificado para el reemplazo, pero mantendré la lógica original)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY,
                    point_id INTEGER,
                    user_name TEXT,
                    content TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_point FOREIGN KEY (point_id) REFERENCES points(id) ON DELETE CASCADE
                )
            ''')
            
            # Tabla de Usuarios
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

            # Tabla de Capas de Datos (NUEVA)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS layers (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    file_type TEXT NOT NULL, -- 'shp', 'csv', 'geojson'
                    url TEXT NOT NULL,
                    description TEXT,
                    is_visible BOOLEAN DEFAULT true,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT
                )
            ''')

            # Tabla de Solicitudes de Recuperación (Respaldo si falla el correo)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovery_requests (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL,
                    full_name TEXT,
                    email TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Creamos el admin inicial
            raw_admin_pass = os.environ.get("ADMIN_PASSWORD", "uv2026")
            admin_pass = pwd_context.hash(raw_admin_pass)
            
            # 1. Admin general
            cursor.execute('''
                INSERT INTO users (username, password, full_name, email, university, role) 
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING
            ''', ('admin', admin_pass, 'Administrador SIG', 'admin@uv.mx', 'Universidad Veracruzana', 'admin'))

            # 2. Director: Angel Fernando Arguello
            director_pass = pwd_context.hash("Arguello2026")
            cursor.execute('''
                INSERT INTO users (username, password, full_name, email, university, role) 
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (username) DO NOTHING
            ''', ('angel.arguello', director_pass, 'Angel Fernando Arguello', 'a_arguello@uv.mx', 'Universidad Veracruzana', 'admin'))
            
            conn.commit()
            cursor.close()
            print("Base de datos inicializada correctamente en Supabase.")
        except Exception as e:
            print(f"Error crítico inicializando base de datos: {e}")

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

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class ForgotPassword(BaseModel):
    user_identifier: str

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
        with get_db_conn() as conn:
            if not conn: raise credentials_exception
            cursor = conn.cursor()
            cursor.execute('SELECT username, full_name, role FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
        
        if user is None:
            raise credentials_exception
            
        return dict(user) 
    except JWTError:
        raise credentials_exception

# --- RUTAS DE LA API - PUNTOS ---

@app.get("/api/v1/points")
async def get_points():
    with get_db_conn() as conn:
        if not conn:
            return []
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, category, subcategory, description, address, lat, lng, image_url, timestamp, likes, created_by_name FROM points')
        rows = cursor.fetchall()
        cursor.close()
        return [dict(row) for row in rows]

# --- NUEVOS ENDPOINTS SOCIALES ---

@app.post("/api/v1/points/{point_id}/like")
async def like_point(point_id: int, current_user: dict = Depends(get_current_user)):
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
        cursor = conn.cursor()
        cursor.execute('UPDATE points SET likes = likes + 1 WHERE id = %s', (point_id,))
        conn.commit()
        cursor.close()
    return {"status": "success"}

@app.post("/api/v1/points/{point_id}/comments")
async def add_comment(point_id: int, comment: CommentCreate, current_user: dict = Depends(get_current_user)):
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO comments (point_id, user_name, content) 
            VALUES (%s, %s, %s)
        ''', (point_id, current_user['full_name'], comment.content))
        conn.commit()
        cursor.close()
    return {"status": "success"}

@app.get("/api/v1/points/{point_id}/comments")
async def get_comments(point_id: int):
    with get_db_conn() as conn:
        if not conn: return []
        cursor = conn.cursor()
        cursor.execute('SELECT id, user_name, content, timestamp FROM comments WHERE point_id = %s ORDER BY timestamp DESC', (point_id,))
        rows = cursor.fetchall()
        cursor.close()
    return [dict(row) for row in rows]

@app.post("/api/v1/upload")
async def upload_image(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    # 1. Validar extensión de archivo
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
    ext = file.filename.split(".")[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Tipo de archivo no permitido. Solo imágenes (png, jpg, jpeg, gif, webp)")

    # 2. Validar tamaño (Ejem: 5MB máx)
    MAX_FILE_SIZE = 5 * 1024 * 1024 # 5MB
    # Nota: Spooling del archivo para leer tamaño
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="La imagen es demasiado grande. Máximo 5MB.")
    
    # Reiniciar el puntero del archivo para guardar
    await file.seek(0)

    # Generar nombre único
    filename = f"{uuid.uuid4()}.{ext}"
    
    if s3_client:
        try:
            # Subir directamente a S3 con ACL de lectura pública
            s3_client.upload_fileobj(
                file.file,
                AWS_BUCKET_NAME,
                filename,
                ExtraArgs={'ACL': 'public-read', 'ContentType': file.content_type}
            )
            
            # Construir URL pública (formato universal)
            file_url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{filename}"
            if AWS_REGION == "us-east-1":
                # us-east-1 a veces usa este formato directo
                file_url = f"https://{AWS_BUCKET_NAME}.s3.amazonaws.com/{filename}"
                
            return {"url": file_url}
            
        except NoCredentialsError:
            raise HTTPException(status_code=500, detail="Error de credenciales en S3")
        except Exception as e:
            print(f"Error S3: {e}")
            # Intentar fallback local si falla S3
            await file.seek(0)
            file_path = os.path.join(UPLOAD_DIR, filename)
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            return {"url": f"/uploads/{filename}"}
    else:
        # Fallback LOCAL
        file_path = os.path.join(UPLOAD_DIR, filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return {"url": f"/uploads/{filename}"}

@app.post("/api/v1/points")
async def save_point(point: Point, current_user: dict = Depends(get_current_user)):
    try:
        with get_db_conn() as conn:
            if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO points (name, category, subcategory, description, address, lat, lng, image_url, created_by, created_by_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (point.name, point.category, point.subcategory, point.description, point.address, point.lat, point.lng, point.image_url, current_user['username'], current_user['full_name']))
            conn.commit()
            point_id = cursor.fetchone()['id']
            cursor.close()
        return {"status": "success", "id": point_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno al guardar punto")

# --- ENDPOINT DE ESTADÍSTICAS / INFORMES ---

@app.get("/api/v1/admin/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado")
        
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
        cursor = conn.cursor()
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
    return [dict(row) for row in rows]

@app.put("/api/v1/points/{point_id}")
async def update_point(point_id: int, point: Point, current_user: dict = Depends(get_current_user)):
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
        cursor = conn.cursor()
        # Verificar que el punto existe y pertenece al usuario (o es admin)
        cursor.execute('SELECT created_by FROM points WHERE id = %s', (point_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Punto no encontrado")
        if current_user.get("role") != "admin" and row["created_by"] != current_user["username"]:
            raise HTTPException(status_code=403, detail="No tienes permiso para editar este punto")
        cursor.execute('''
            UPDATE points
            SET name=%s, category=%s, subcategory=%s, description=%s, address=%s,
                lat=%s, lng=%s, image_url=%s
            WHERE id=%s
        ''', (point.name, point.category, point.subcategory, point.description,
              point.address, point.lat, point.lng, point.image_url, point_id))
        conn.commit()
        cursor.close()
    return {"status": "success", "id": point_id}

@app.delete("/api/v1/points/{point_id}")
async def delete_point(point_id: int, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo el admin puede borrar.")
        
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
        cursor = conn.cursor()
        cursor.execute('DELETE FROM points WHERE id = %s', (point_id,))
        conn.commit()
        cursor.close()
    return {"status": "success"}

# --- RUTAS DE AUTENTICACIÓN ---

# Función de validación de correo eliminada para permitir acceso general (Gmail, etc.)

@app.post("/api/v1/auth/register")
async def register(user: UserCreate):
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
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
            cursor.close() # Changed from `return user` to `cursor.close()` to maintain correctness

@app.post("/api/v1/auth/forgot-password")
async def forgot_password(request: ForgotPassword):
    # 1. Buscar si el usuario existe (opcional, por seguridad podrías no validarlo)
    user_data = None
    with get_db_conn() as conn:
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, full_name, email FROM users WHERE username = %s OR email = %s", 
                         (request.user_identifier, request.user_identifier))
            user_data = cursor.fetchone()
            cursor.close()

    if not user_data:
        # Por seguridad no decimos si existe o no, pero mandamos éxito falso
        return {"status": "success", "message": "Si el usuario existe, se ha enviado la notificación al administrador."}

    # 2. Intentar enviar correo al Admin
    if not SMTP_PASS:
        print(f"AVISO: Petición de recuperación para {user_data['username']}, pero SMTP no está configurado.")
        return {"status": "success", "message": "Solicitud registrada. El administrador revisará tu caso."}

    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_NOTIFY_EMAIL
        msg['Subject'] = f"🚀 SOLICITUD DE RECUPERACIÓN: {user_data['username']}"

        body = f"""
        Hola Administrador,
        
        El usuario {user_data['full_name']} ({user_data['username']}) ha solicitado recuperar su contraseña en el Geoportal Interactivo.
        
        Detalles:
        - Usuario: {user_data['username']}
        - Correo registrado del usuario: {user_data['email']}
        - Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Por favor, contacta con el usuario para realizar el cambio manual o verifica su identidad.
        """
        msg.attach(MIMEText(body, 'plain'))

        # 3. Guardar en Base de Datos (Respaldo garantizado)
        try:
            with get_db_conn() as conn:
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO recovery_requests (username, full_name, email) VALUES (%s, %s, %s)",
                                 (user_data['username'], user_data['full_name'], user_data['email']))
                    conn.commit()
                    cursor.close()
        except Exception as dbe:
            print(f"Error guardando respaldo de recuperación: {dbe}")

        # 4. Enviar Correo con SMTP_SSL (Puerto 465 - Recomendado para Gmail)
        try:
            print(f"DEBUG: Intentando enviar correo vía SSL (Puerto 465)...")
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=15) as server:
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            
            return {"status": "success", "message": "Solicitud enviada al administrador correctamente por correo y base de datos."}
        except Exception as e:
            print(f"DEBUG: Fallo SSL (465): {e}. Intentando puerto 587 como último recurso...")
            try:
                with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.send_message(msg)
                return {"status": "success", "message": "Solicitud enviada (vía TLS)."}
            except Exception as e2:
                print(f"DEBUG: Todos los puertos fallaron: {e2}")
                return {"status": "success", "message": "Tu solicitud ha sido registrada en el panel del administrador. Él revisará tu cuenta pronto."}
            
    except Exception as e:
        print(f"Error crítico: {e}")
        return {"status": "error", "message": "Ocurrió un error al procesar tu solicitud."}

@app.get("/api/v1/auth/recovery-requests")
async def get_recovery_requests(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="No autorizado")
    
    with get_db_conn() as conn:
        if not conn: return []
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM recovery_requests ORDER BY created_at DESC")
        requests = cursor.fetchall()
        cursor.close()
    return [dict(r) for r in requests]

@app.post("/api/v1/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
        cursor = conn.cursor()
        cursor.execute('SELECT username, password, full_name, university, role FROM users WHERE username = %s', (form_data.username,))
        user = cursor.fetchone()
        cursor.close()
    
    if not user or not pwd_context.verify(form_data.password, user['password']):
        raise HTTPException(status_code=400, detail="Usuario o contraseña incorrectos")
    
    access_token = create_access_token(data={"sub": user['username'], "name": user['full_name']})
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
    if not token: raise HTTPException(status_code=400, detail="Token ausente")
        
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['email']
        name = idinfo.get('name', email.split('@')[0])
        picture = idinfo.get('picture')
        
        with get_db_conn() as conn:
            if not conn: raise HTTPException(status_code=503, detail="BD no disponible")
            cursor = conn.cursor()
            cursor.execute('SELECT username, full_name, email, university, role FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            
            if not user:
                username = email.split('@')[0]
                dummy_pass = pwd_context.hash(os.urandom(16).hex())
                cursor.execute('''
                    INSERT INTO users (username, password, full_name, email, university, role)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (username, dummy_pass, name, email, 'Google Account', 'user'))
                conn.commit()
                cursor.execute('SELECT username, full_name, email, university, role FROM users WHERE email = %s', (email,))
                user = cursor.fetchone()
            cursor.close()
        
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

@app.post("/api/v1/auth/change-password")
async def change_password(data: PasswordChange, current_user: dict = Depends(get_current_user)):
    with get_db_conn() as conn:
        if not conn: raise HTTPException(status_code=503, detail="Base de datos no disponible")
        cursor = conn.cursor()
        
        # Obtener contraseña actual del usuario
        cursor.execute('SELECT password FROM users WHERE username = %s', (current_user['username'],))
        user = cursor.fetchone()
        
        if not user or not pwd_context.verify(data.old_password, user['password']):
            cursor.close()
            raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta")
            
        # Actualizar con la nueva contraseña
        new_hashed = pwd_context.hash(data.new_password)
        cursor.execute('UPDATE users SET password = %s WHERE username = %s', (new_hashed, current_user['username']))
        conn.commit()
        cursor.close()
        
    return {"status": "success", "message": "Contraseña actualizada correctamente"}

# --- RUTAS DE LA API - RUTAS ---

@app.get("/api/v1/rutas")
async def obtener_rutas():
    routes_path = os.path.join("data", "routes")
    files = []
    if os.path.exists(routes_path):
        files = [f for f in os.listdir(routes_path) if f.endswith('.geojson')]
    return {"status": "success", "count": len(files), "files": files}

# --- GESTIÓN DE CAPAS DE DATOS ---

@app.post("/api/v1/layers/upload")
async def upload_layer(
    file: UploadFile = File(...),
    name: str = Form(...),
    description: Optional[str] = Form(None),
    current_user: dict = Depends(get_current_user)
):
    # Validar extensión
    ext = file.filename.split('.')[-1].lower()
    if ext not in ['zip', 'csv', 'geojson', 'json']:
        raise HTTPException(status_code=400, detail="Formato de archivo no permitido. Use .zip (para SHP), .csv o .geojson")

    file_type = 'shp' if ext == 'zip' else ext
    if ext == 'json': file_type = 'geojson'

    filename = f"layers/{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    file_url = f"/uploads/{filename}"

    try:
        # TEMPORAL: Usar local primero para diagnóstico
        print("DEBUG: Usando almacenamiento local temporalmente para descartar errores de AWS.")
        os.makedirs(os.path.join(UPLOAD_DIR, "layers"), exist_ok=True)
        local_filename = f"layers/{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        local_path = os.path.join(UPLOAD_DIR, local_filename)
        
        with open(local_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        file_url = f"/uploads/{local_filename}"

        # Intentar S3 solo si el local funcionó y solo como respaldo por ahora
        if s3_client:
            print(f"DEBUG: Intentando respaldo en S3 a bucket {AWS_BUCKET_NAME}...")
            try:
                # Reiniciar el puntero del archivo para S3
                file.file.seek(0)
                s3_client.upload_fileobj(
                    file.file, 
                    AWS_BUCKET_NAME, 
                    local_filename,
                    ExtraArgs={'ACL': 'public-read'} # Asegurar que sea público
                )
                
                # URL preferida para us-east-1
                if AWS_REGION == "us-east-1":
                    file_url = f"https://{AWS_BUCKET_NAME}.s3.amazonaws.com/{local_filename}"
                else:
                    file_url = f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{local_filename}"
                
                print(f"DEBUG: Subida a S3 exitosa: {file_url}")
            except Exception as s3e:
                print(f"DEBUG: Fallo S3: {s3e}")
                # El file_url se queda como el local f"/uploads/{local_filename}"
        
        # Guardar en Base de Datos
        with get_db_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO layers (name, file_type, url, description, created_by)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            ''', (name, file_type, file_url, description, current_user['username']))
            layer_id = cursor.fetchone()['id']
            conn.commit()
            cursor.close()

        return {"status": "success", "layer_id": layer_id, "url": file_url}

    except Exception as e:
        print(f"Error subiendo capa: {e}")
        raise HTTPException(status_code=500, detail="Error interno al procesar el archivo")

@app.get("/api/v1/layers")
async def list_layers():
    with get_db_conn() as conn:
        if not conn: return {"layers": []}
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM layers WHERE is_visible = true ORDER BY created_at DESC")
        layers = cursor.fetchall()
        cursor.close()
    return {"layers": [dict(l) for l in layers]}

@app.delete("/api/v1/layers/{layer_id}")
async def delete_layer(layer_id: int, current_user: dict = Depends(get_current_user)):
    try:
        with get_db_conn() as conn:
            if not conn: raise HTTPException(status_code=503, detail="Base de datos no disponible")
            cursor = conn.cursor()
            # 1. Obtener datos de la capa antes de borrar
            cursor.execute("SELECT url, created_by FROM layers WHERE id = %s", (layer_id,))
            layer = cursor.fetchone()
            
            if not layer:
                raise HTTPException(status_code=404, detail="Capa no encontrada")
            
            # 2. Verificar permisos (solo dueño o admin)
            if layer['created_by'] != current_user['username'] and current_user['role'] != 'admin':
                raise HTTPException(status_code=403, detail="No tienes permiso para borrar esta capa")
            
            # 3. Borrar de S3 si aplica
            file_url = layer['url']
            if s3_client and "amazonaws.com" in file_url:
                try:
                    # Extraer el key del URL
                    # Ej: https://bucket.s3.region.amazonaws.com/layers/archivo.zip
                    s3_key = file_url.split(".com/")[-1]
                    s3_client.delete_object(Bucket=AWS_BUCKET_NAME, Key=s3_key)
                    print(f"DEBUG: Archivo borrado de S3: {s3_key}")
                except Exception as s3e:
                    print(f"DEBUG: Error borrando de S3 (posiblemente ya no existe): {s3e}")
            elif file_url.startswith("/uploads/"):
                # Borrado local
                local_path = os.path.join(UPLOAD_DIR, file_url.replace("/uploads/", ""))
                if os.path.exists(local_path):
                    os.remove(local_path)
                    print(f"DEBUG: Archivo local borrado: {local_path}")

            # 4. Borrar de la base de datos
            cursor.execute("DELETE FROM layers WHERE id = %s", (layer_id,))
            conn.commit()
            cursor.close()

        return {"status": "success", "message": "Capa eliminada correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error borrando capa: {e}")
        raise HTTPException(status_code=500, detail="Error interno al eliminar la capa")

# Montamos carpetas de recursos
app.mount("/js", StaticFiles(directory="js"), name="js")
app.mount("/css", StaticFiles(directory="css"), name="css")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Ruta para servir el index.html desde la raíz (para compatibilidad con GitHub Pages)
@app.get("/")
async def read_index():
    return FileResponse('index.html')

# Servir archivos GeoJSON y JSON desde la raíz
@app.get("/{filename}.geojson")
async def get_geojson(filename: str):
    path = f"{filename}.geojson"
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404)

@app.get("/{filename}.json")
async def get_json(filename: str):
    path = f"{filename}.json"
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404)

# Imágenes sueltas en la raíz
@app.get("/{filename}.png")
async def get_png(filename: str):
    path = f"{filename}.png"
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404)

@app.get("/{filename}.jpg")
async def get_jpg(filename: str):
    path = f"{filename}.jpg"
    if os.path.exists(path):
        return FileResponse(path)
    raise HTTPException(status_code=404)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
