import psycopg2
from psycopg2 import extras
import os
import json
from dotenv import load_dotenv

load_dotenv()

def check_db():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("❌ Error: DATABASE_URL no encontrada en .env")
        return

    try:
        conn = psycopg2.connect(db_url, sslmode='require')
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        
        # 1. Verificar tabla 'layers'
        print("\n=== REVISANDO TABLA 'LAYERS' ===")
        cur.execute("SELECT id, name, file_type, url, created_at FROM layers ORDER BY created_at DESC")
        layers = cur.fetchall()
        if not layers:
            print("No hay capas registradas aún.")
        else:
            for l in layers:
                print(f"ID: {l['id']} | Nombre: {l['name']} | Tipo: {l['file_type']} | Creado: {l['created_at']}")
                print(f"   URL: {l['url']}")

        # 2. Verificar tabla 'points' (Marcadores personalizados)
        print("\n=== REVISANDO TABLA 'POINTS' ===")
        cur.execute("SELECT count(*) as total FROM points")
        total_p = cur.fetchone()['total']
        print(f"Total de marcadores guardados: {total_p}")
        
        # 3. Verificar tabla 'users'
        print("\n=== REVISANDO TABLA 'USERS' ===")
        cur.execute("SELECT id, username, role FROM users")
        users = cur.fetchall()
        for u in users:
            print(f"Usuario: {u['username']} | Rol: {u['role']}")

        cur.close()
        conn.close()
        print("\n✅ Conexión a Supabase exitosa y saludable.")
        
    except Exception as e:
        print(f"Error conectando a Supabase: {e}")

if __name__ == "__main__":
    check_db()
