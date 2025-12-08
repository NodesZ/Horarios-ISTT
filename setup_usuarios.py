"""
Script de Inicialización Automática para Render.com
Sistema de Gestión de Horarios - ISTT
"""

import sqlite3
import hashlib
import os
import secrets
import string
from datetime import datetime

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generar_password_segura(longitud=16):
    """Genera una contraseña aleatoria segura"""
    caracteres = string.ascii_letters + string.digits + "!@#$%&*"
    return ''.join(secrets.choice(caracteres) for _ in range(longitud))

def inicializar_usuarios_sistema(db_path):
    """
    Inicializa usuarios del sistema desde variables de entorno o genera credenciales aleatorias.
    Retorna un diccionario con las credenciales creadas.
    """
    
    print("\n" + "=" * 80)
    print("INICIALIZACIÓN DE USUARIOS DEL SISTEMA")
    print("=" * 80)
    
    try:
        conn = sqlite3.connect(db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Verificar si ya existen usuarios
        c.execute('SELECT COUNT(*) as total FROM usuarios')
        total_usuarios = c.fetchone()['total']
        
        if total_usuarios > 0:
            print(f"✓ Sistema ya inicializado. Existen {total_usuarios} usuario(s).")
            print("=" * 80 + "\n")
            conn.close()
            return None
        
        print("⚙️  Sistema sin usuarios. Procediendo a inicialización automática...\n")
        
        # Leer credenciales desde variables de entorno o generar aleatorias
        credenciales_creadas = {}
        
        # ==================== RECTORADO ====================
        print("-" * 80)
        print("USUARIO RECTORADO")
        print("-" * 80)
        
        rectorado_user = os.getenv('RECTORADO_USER', 'rectorado')
        rectorado_pass = os.getenv('RECTORADO_PASS')
        
        if not rectorado_pass:
            rectorado_pass = generar_password_segura(16)
            print("⚠️  Variable RECTORADO_PASS no definida. Generando contraseña aleatoria...")
        else:
            print("✓ Usando RECTORADO_PASS desde variable de entorno.")
        
        rectorado_nombre = os.getenv('RECTORADO_NOMBRE', 'Usuario Rectorado')
        rectorado_cargo = os.getenv('RECTORADO_CARGO', 'Rectorado')
        
        password_hash = hash_password(rectorado_pass)
        c.execute('''
            INSERT INTO usuarios (usuario, password, nombre, cargo, rol, activo)
            VALUES (?, ?, ?, ?, 'rectorado', 1)
        ''', (rectorado_user, password_hash, rectorado_nombre, rectorado_cargo))
        
        rectorado_id = c.lastrowid
        
        credenciales_creadas['rectorado'] = {
            'usuario': rectorado_user,
            'password': rectorado_pass,
            'nombre': rectorado_nombre,
            'cargo': rectorado_cargo,
            'rol': 'rectorado'
        }
        
        print(f"✓ Usuario Rectorado creado:")
        print(f"  ID:       {rectorado_id}")
        print(f"  Usuario:  {rectorado_user}")
        print(f"  Nombre:   {rectorado_nombre}")
        print(f"  Cargo:    {rectorado_cargo}")
        
        # ==================== COORDINADOR ====================
        print("\n" + "-" * 80)
        print("USUARIO COORDINADOR")
        print("-" * 80)
        
        coordinador_user = os.getenv('COORDINADOR_USER', 'coordinador')
        coordinador_pass = os.getenv('COORDINADOR_PASS')
        
        if not coordinador_pass:
            coordinador_pass = generar_password_segura(16)
            print("⚠️  Variable COORDINADOR_PASS no definida. Generando contraseña aleatoria...")
        else:
            print("✓ Usando COORDINADOR_PASS desde variable de entorno.")
        
        coordinador_nombre = os.getenv('COORDINADOR_NOMBRE', 'Coordinador de Carrera')
        coordinador_cargo = os.getenv('COORDINADOR_CARGO', 'Coordinador/a')
        
        password_hash = hash_password(coordinador_pass)
        c.execute('''
            INSERT INTO usuarios (usuario, password, nombre, cargo, rol, activo, creado_por)
            VALUES (?, ?, ?, ?, 'coordinador', 1, ?)
        ''', (coordinador_user, password_hash, coordinador_nombre, coordinador_cargo, rectorado_id))
        
        coordinador_id = c.lastrowid
        
        credenciales_creadas['coordinador'] = {
            'usuario': coordinador_user,
            'password': coordinador_pass,
            'nombre': coordinador_nombre,
            'cargo': coordinador_cargo,
            'rol': 'coordinador'
        }
        
        print(f"✓ Usuario Coordinador creado:")
        print(f"  ID:       {coordinador_id}")
        print(f"  Usuario:  {coordinador_user}")
        print(f"  Nombre:   {coordinador_nombre}")
        print(f"  Cargo:    {coordinador_cargo}")
        
        conn.commit()
        
        # ==================== RESUMEN ====================
        print("\n" + "=" * 80)
        print("✓✓✓ INICIALIZACIÓN COMPLETADA EXITOSAMENTE ✓✓✓")
        print("=" * 80)
        print("\n🔐 CREDENCIALES DE ACCESO (GUÁRDALAS DE FORMA SEGURA):\n")
        
        for rol, datos in credenciales_creadas.items():
            print("-" * 80)
            print(f"ROL: {datos['rol'].upper()}")
            print(f"Usuario:     {datos['usuario']}")
            print(f"Contraseña:  {datos['password']}")
            print(f"Nombre:      {datos['nombre']}")
            print(f"Cargo:       {datos['cargo']}")
        
        print("-" * 80)
        print("\n⚠️  IMPORTANTE:")
        print("   1. Guarda estas credenciales en un lugar seguro")
        print("   2. Cambia las contraseñas inmediatamente después del primer acceso")
        print("   3. Estas credenciales NO se volverán a mostrar")
        print("   4. El coordinador puede crear usuarios docentes desde el panel")
        print("\n" + "=" * 80 + "\n")
        
        # Guardar credenciales en archivo temporal solo en desarrollo
        if os.getenv('FLASK_ENV') != 'production':
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            credenciales_file = f'CREDENCIALES_INICIALES_{timestamp}.txt'
            
            with open(credenciales_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("CREDENCIALES DE ACCESO INICIAL - SISTEMA ISTT\n")
                f.write(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for rol, datos in credenciales_creadas.items():
                    f.write("-" * 80 + "\n")
                    f.write(f"ROL: {datos['rol'].upper()}\n")
                    f.write(f"Usuario:     {datos['usuario']}\n")
                    f.write(f"Contraseña:  {datos['password']}\n")
                    f.write(f"Nombre:      {datos['nombre']}\n")
                    f.write(f"Cargo:       {datos['cargo']}\n")
                    f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write("⚠️  IMPORTANTE:\n")
                f.write("   - Guarda este archivo en un lugar seguro\n")
                f.write("   - Elimina este archivo después de guardar las credenciales\n")
                f.write("   - Cambia las contraseñas inmediatamente\n")
            
            print(f"📄 Credenciales guardadas en: {credenciales_file}")
            print("   (Solo en modo desarrollo - archivo temporal)\n")
        
        conn.close()
        return credenciales_creadas
        
    except sqlite3.Error as e:
        print(f"\n❌ ERROR DE BASE DE DATOS: {e}")
        if conn:
            conn.rollback()
            conn.close()
        raise
    except Exception as e:
        print(f"\n❌ ERROR INESPERADO: {e}")
        if conn:
            conn.rollback()
            conn.close()
        raise

def verificar_sistema_inicializado(db_path):
    """Verifica si el sistema ya tiene usuarios creados"""
    try:
        if not os.path.exists(db_path):
            return False
        
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM usuarios')
        count = c.fetchone()[0]
        conn.close()
        
        return count > 0
    except:
        return False

if __name__ == '__main__':
    # Si se ejecuta directamente (para testing local)
    import sys
    
    db_path = os.path.join('static', 'horarios.db')
    
    if not os.path.exists(db_path):
        print("❌ ERROR: La base de datos no existe.")
        print("   Ejecuta primero 'python app.py' para crear la estructura.")
        sys.exit(1)
    
    try:
        credenciales = inicializar_usuarios_sistema(db_path)
        if credenciales:
            print("✓ Script completado exitosamente.")
        else:
            print("ℹ️  No fue necesario crear usuarios (ya existen).")
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
