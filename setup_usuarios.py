"""
Script de Inicialización Automática para Render.com
Sistema de Gestión de Horarios - ISTT
"""

import sqlite3
import hashlib
import os

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def inicializar_usuarios_sistema(db_path):
    """
    Inicializa usuarios del sistema de forma silenciosa.
    Retorna True si creó usuarios, False si ya existían.
    """
    
    try:
        conn = sqlite3.connect(db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Verificar si ya existen usuarios
        c.execute('SELECT COUNT(*) as total FROM usuarios')
        total_usuarios = c.fetchone()['total']
        
        if total_usuarios > 0:
            conn.close()
            return False
        
        # Crear usuario Rectorado
        rectorado_user = os.getenv('RECTORADO_USER', 'rectorado')
        rectorado_pass = os.getenv('RECTORADO_PASS', 'rectorado2025')
        rectorado_nombre = os.getenv('RECTORADO_NOMBRE', 'Usuario Rectorado')
        rectorado_cargo = os.getenv('RECTORADO_CARGO', 'Rectorado')
        
        password_hash = hash_password(rectorado_pass)
        c.execute('''
            INSERT INTO usuarios (usuario, password, nombre, cargo, rol, activo)
            VALUES (?, ?, ?, ?, 'rectorado', 1)
        ''', (rectorado_user, password_hash, rectorado_nombre, rectorado_cargo))
        
        rectorado_id = c.lastrowid
        
        # Crear usuario Coordinador
        coordinador_user = os.getenv('COORDINADOR_USER', 'coordinador')
        coordinador_pass = os.getenv('COORDINADOR_PASS', 'coordinador2025')
        coordinador_nombre = os.getenv('COORDINADOR_NOMBRE', 'Coordinador de Carrera')
        coordinador_cargo = os.getenv('COORDINADOR_CARGO', 'Coordinador/a')
        
        password_hash = hash_password(coordinador_pass)
        c.execute('''
            INSERT INTO usuarios (usuario, password, nombre, cargo, rol, activo, creado_por)
            VALUES (?, ?, ?, ?, 'coordinador', 1, ?)
        ''', (coordinador_user, password_hash, coordinador_nombre, coordinador_cargo, rectorado_id))
        
        coordinador_id = c.lastrowid
        
        # Crear usuario Docente por defecto
        docente_user = os.getenv('DOCENTE_USER', 'docente')
        docente_pass = os.getenv('DOCENTE_PASS', 'docente2025')
        docente_nombre = os.getenv('DOCENTE_NOMBRE', 'Docente Demo')
        docente_cargo = os.getenv('DOCENTE_CARGO', 'Docente')
        
        password_hash = hash_password(docente_pass)
        c.execute('''
            INSERT INTO usuarios (usuario, password, nombre, cargo, rol, activo, creado_por)
            VALUES (?, ?, ?, ?, 'docente', 1, ?)
        ''', (docente_user, password_hash, docente_nombre, docente_cargo, coordinador_id))
        
        conn.commit()
        conn.close()
        
        return True
        
    except Exception:
        if conn:
            conn.rollback()
            conn.close()
        return False

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
