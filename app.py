"""
Sistema de Gestión de Horarios - ISTT
VERSIÓN OPTIMIZADA PARA PRODUCCIÓN CON SOPORTE MULTI-USUARIO
Compatible con Windows y Linux
PARTE 1 DE 3: Configuración, Base de Datos y Funciones Auxiliares
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, make_response
from werkzeug.utils import secure_filename
import os
import sys
import json
import sqlite3
from functools import wraps
from datetime import datetime, timedelta
import hashlib
import copy
from io import BytesIO
import logging
from logging.handlers import RotatingFileHandler
import traceback
import threading
import time
from contextlib import contextmanager
from pathlib import Path
import platform
import secrets

# ============================================================================
# CONFIGURACIÓN DE LA APLICACIÓN
# ============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['DATABASE'] = os.path.join('static', 'horarios.db')
app.config['LOG_FOLDER'] = 'logs'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('HTTPS', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['DB_TIMEOUT'] = 30.0
app.config['DB_MAX_RETRIES'] = 5
app.config['DB_RETRY_DELAY'] = 0.1

IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

for folder in [app.config['UPLOAD_FOLDER'], 'static', app.config['LOG_FOLDER']]:
    Path(folder).mkdir(parents=True, exist_ok=True)

_db_write_lock = threading.RLock()
_file_operation_lock = threading.Lock()

PERIODOS_VALIDOS_TAES = ['6', '7', '9', '10']
HORAS_MAXIMAS_POR_DIA = 8

# ============================================================================
# SISTEMA DE LOGGING
# ============================================================================

def setup_logging():
    log_format = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | '
        'Usuario: %(usuario)s | IP: %(ip)s | '
        'PID: %(process)d | Thread: %(thread)d | '
        'Acción: %(accion)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    handlers = {
        'general': ('sistema.log', logging.INFO, 20),
        'error': ('errores.log', logging.ERROR, 10),
        'auth': ('autenticacion.log', logging.INFO, 10),
        'horarios': ('horarios.log', logging.INFO, 15),
        'admin': ('administracion.log', logging.INFO, 10),
        'concurrent': ('concurrencia.log', logging.WARNING, 10),
    }
    
    loggers = {}
    
    for name, (filename, level, backup_count) in handlers.items():
        handler = RotatingFileHandler(
            os.path.join(app.config['LOG_FOLDER'], filename),
            maxBytes=10*1024*1024,
            backupCount=backup_count,
            encoding='utf-8'
        )
        handler.setLevel(level)
        handler.setFormatter(log_format)
        
        logger = logging.getLogger(name) if name != 'general' else app.logger
        logger.setLevel(level)
        logger.addHandler(handler)
        loggers[name] = logger
    
    error_handler = handlers['error']
    for logger in loggers.values():
        if logger != loggers['error']:
            logger.addHandler(loggers['error'].handlers[0])
    
    return loggers

loggers = setup_logging()

def log_action(logger_name, action, message, level='info', extra_data=None):
    logger = loggers.get(logger_name, loggers.get('general', app.logger))
    
    try:
        usuario = session.get('usuario', 'ANONIMO')
        usuario_id = session.get('usuario_id', 'N/A')
        rol = session.get('rol', 'N/A')
    except RuntimeError:
        usuario = 'SISTEMA'
        usuario_id = 'N/A'
        rol = 'SISTEMA'
    
    try:
        ip = request.remote_addr if request else 'N/A'
    except RuntimeError:
        ip = 'N/A'
    
    extra = {
        'usuario': f"{usuario} (ID:{usuario_id}, Rol:{rol})",
        'ip': ip,
        'accion': action
    }
    
    full_message = message
    if extra_data:
        extra_details = " | ".join([f"{k}={v}" for k, v in extra_data.items()])
        full_message = f"{message} | {extra_details}"
    
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(full_message, extra=extra)

def log_error_with_traceback(logger_name, action, error, extra_data=None):
    error_msg = f"{str(error)}\n{traceback.format_exc()}"
    log_action(logger_name, action, error_msg, level='error', extra_data=extra_data)

# ============================================================================
# GESTIÓN DE BASE DE DATOS
# ============================================================================

@contextmanager
def get_db_connection(write_mode=False):
    conn = None
    lock_acquired = False
    
    try:
        if write_mode:
            _db_write_lock.acquire()
            lock_acquired = True
        
        conn = sqlite3.connect(
            app.config['DATABASE'],
            timeout=app.config['DB_TIMEOUT'],
            isolation_level='IMMEDIATE' if write_mode else 'DEFERRED',
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA synchronous=NORMAL')
        
        yield conn
        
        if write_mode:
            conn.commit()
            
    except sqlite3.OperationalError as e:
        if conn:
            conn.rollback()
        log_action('concurrent', 'DB_LOCK_ERROR', 
                   f'Error de bloqueo de BD: {str(e)}',
                   level='warning',
                   extra_data={'write_mode': write_mode})
        raise
        
    except Exception as e:
        if conn:
            conn.rollback()
        log_error_with_traceback('concurrent', 'DB_ERROR', e)
        raise
        
    finally:
        if conn:
            conn.close()
        if lock_acquired:
            _db_write_lock.release()

def execute_with_retry(func, max_retries=None, *args, **kwargs):
    if max_retries is None:
        max_retries = app.config['DB_MAX_RETRIES']
    
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            last_exception = e
            error_msg = str(e).lower()
            
            if 'locked' in error_msg or 'busy' in error_msg:
                if attempt < max_retries - 1:
                    wait_time = app.config['DB_RETRY_DELAY'] * (2 ** attempt)
                    log_action('concurrent', 'DB_RETRY', 
                               f'Reintentando operación de BD (intento {attempt + 1}/{max_retries})',
                               level='warning',
                               extra_data={'wait_time': wait_time})
                    time.sleep(wait_time)
                    continue
            
            raise
    
    log_action('concurrent', 'DB_RETRY_EXHAUSTED', 
               f'Reintentos agotados después de {max_retries} intentos',
               level='error')
    raise last_exception

# ============================================================================
# GESTIÓN DE ARCHIVOS
# ============================================================================

def guardar_archivo_horario(horario_id, horario_data):
    def _guardar():
        archivo_path = Path(app.config['UPLOAD_FOLDER']) / f'horario_{horario_id}.hored'
        archivo_temp = archivo_path.with_suffix('.hored.tmp')
        
        try:
            with open(archivo_temp, 'w', encoding='utf-8') as f:
                json.dump(horario_data, f, ensure_ascii=False, indent=2)
            
            archivo_temp.replace(archivo_path)
            
            file_size = archivo_path.stat().st_size
            log_action('horarios', 'ARCHIVO_GUARDADO', 
                       f'Archivo horario_{horario_id}.hored guardado exitosamente',
                       extra_data={'horario_id': horario_id, 'tamaño_bytes': file_size})
            return True
            
        except Exception as e:
            if archivo_temp.exists():
                archivo_temp.unlink()
            raise e
    
    try:
        with _file_operation_lock:
            return _guardar()
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_GUARDAR_ARCHIVO', e,
                                extra_data={'horario_id': horario_id})
        return False

def eliminar_archivo_horario(horario_id):
    def _eliminar():
        archivo_path = Path(app.config['UPLOAD_FOLDER']) / f'horario_{horario_id}.hored'
        
        if archivo_path.exists():
            file_size = archivo_path.stat().st_size
            archivo_path.unlink()
            log_action('horarios', 'ARCHIVO_ELIMINADO', 
                       f'Archivo horario_{horario_id}.hored eliminado del sistema',
                       extra_data={'horario_id': horario_id, 'tamaño_liberado_bytes': file_size})
            return True
        else:
            log_action('horarios', 'ARCHIVO_NO_ENCONTRADO', 
                       f'Intento de eliminar archivo inexistente: horario_{horario_id}.hored',
                       level='warning',
                       extra_data={'horario_id': horario_id})
            return False
    
    try:
        with _file_operation_lock:
            return _eliminar()
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_ELIMINAR_ARCHIVO', e,
                                extra_data={'horario_id': horario_id})
        return False

def limpiar_archivos_huerfanos():
    def _limpiar():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM horarios')
            horarios_ids = {str(row['id']) for row in c.fetchall()}
        
        archivos_eliminados = 0
        espacio_liberado = 0
        upload_folder = Path(app.config['UPLOAD_FOLDER'])
        
        for archivo_path in upload_folder.glob('horario_*.hored'):
            horario_id = archivo_path.stem.replace('horario_', '')
            
            if horario_id not in horarios_ids:
                file_size = archivo_path.stat().st_size
                archivo_path.unlink()
                archivos_eliminados += 1
                espacio_liberado += file_size
        
        if archivos_eliminados > 0:
            log_action('horarios', 'LIMPIEZA_ARCHIVOS_HUERFANOS', 
                       f'Limpieza completada: {archivos_eliminados} archivos eliminados',
                       extra_data={
                           'archivos_eliminados': archivos_eliminados,
                           'espacio_liberado_mb': round(espacio_liberado / (1024*1024), 2)
                       })
        
        return archivos_eliminados, espacio_liberado
    
    try:
        with _file_operation_lock:
            return execute_with_retry(_limpiar)
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_LIMPIEZA_HUERFANOS', e)
        return 0, 0

# ============================================================================
# INICIALIZACIÓN DE BASE DE DATOS
# ============================================================================

def init_db():
    log_action('general', 'INICIO_BD', 'Iniciando base de datos del sistema')
    
    def _init():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('PRAGMA foreign_keys=ON')
            
            # Tabla de usuarios
            c.execute('''
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    nombre TEXT NOT NULL,
                    cargo TEXT NOT NULL,
                    rol TEXT NOT NULL CHECK(rol IN ('docente', 'coordinador', 'rectorado')),
                    activo INTEGER DEFAULT 1,
                    creado_por INTEGER,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (creado_por) REFERENCES usuarios(id)
                )
            ''')
            
            # Tabla de horarios
            c.execute('''
                CREATE TABLE IF NOT EXISTS horarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario_id INTEGER NOT NULL,
                    nombre_archivo TEXT NOT NULL,
                    contenido_json TEXT NOT NULL,
                    estado TEXT NOT NULL CHECK(estado IN ('borrador', 'revision_coordinador', 'revision_rectorado', 'rechazado_coordinador', 'rechazado_rectorado', 'aprobado')),
                    revisor_coordinador_id INTEGER,
                    revisor_rectorado_id INTEGER,
                    fecha_carga TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    fecha_envio_revision TIMESTAMP,
                    fecha_revision_coordinador TIMESTAMP,
                    fecha_revision_rectorado TIMESTAMP,
                    fecha_aprobacion TIMESTAMP,
                    version INTEGER DEFAULT 1,
                    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
                    FOREIGN KEY (revisor_coordinador_id) REFERENCES usuarios(id),
                    FOREIGN KEY (revisor_rectorado_id) REFERENCES usuarios(id)
                )
            ''')
            
            # Índices para horarios
            c.execute('CREATE INDEX IF NOT EXISTS idx_horarios_usuario ON horarios(usuario_id)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_horarios_estado ON horarios(estado)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_usuarios_rol ON usuarios(rol, activo)')
            
            # Tabla de observaciones
            c.execute('''
                CREATE TABLE IF NOT EXISTS observaciones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    horario_id INTEGER NOT NULL,
                    revisor_id INTEGER NOT NULL,
                    tipo_revisor TEXT NOT NULL CHECK(tipo_revisor IN ('coordinador', 'rectorado')),
                    observacion_general TEXT,
                    fecha_observacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    activa INTEGER DEFAULT 1,
                    FOREIGN KEY (horario_id) REFERENCES horarios(id),
                    FOREIGN KEY (revisor_id) REFERENCES usuarios(id)
                )
            ''')
            
            c.execute('CREATE INDEX IF NOT EXISTS idx_observaciones_horario ON observaciones(horario_id)')
            
            # Tabla de observaciones específicas
            c.execute('''
                CREATE TABLE IF NOT EXISTS observaciones_especificas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observacion_id INTEGER NOT NULL,
                    dia_id TEXT NOT NULL,
                    periodo_id TEXT NOT NULL,
                    comentario TEXT NOT NULL,
                    FOREIGN KEY (observacion_id) REFERENCES observaciones(id)
                )
            ''')
            
            # Tabla de asignación de actividades
            c.execute('''
                CREATE TABLE IF NOT EXISTS asignacion_actividades (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario_id INTEGER NOT NULL,
                    codigo_actividad TEXT NOT NULL,
                    horas_asignadas INTEGER NOT NULL DEFAULT 0,
                    fecha_asignacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    asignado_por INTEGER,
                    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
                    FOREIGN KEY (asignado_por) REFERENCES usuarios(id),
                    UNIQUE(usuario_id, codigo_actividad)
                )
            ''')
            
            c.execute('CREATE INDEX IF NOT EXISTS idx_asignacion_usuario ON asignacion_actividades(usuario_id)')
            
            # Tabla de configuración
            c.execute('''
                CREATE TABLE IF NOT EXISTS configuracion (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    clave TEXT UNIQUE NOT NULL,
                    valor TEXT NOT NULL,
                    fecha_modificacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabla de actividades complementarias
            c.execute('''
                CREATE TABLE IF NOT EXISTS actividades_complementarias (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    codigo TEXT UNIQUE NOT NULL,
                    descripcion TEXT NOT NULL,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    creado_por INTEGER,
                    FOREIGN KEY (creado_por) REFERENCES usuarios(id)
                )
            ''')
            
            # Configuración inicial del ciclo académico
            c.execute('''
                INSERT OR IGNORE INTO configuracion (clave, valor)
                VALUES ('ciclo_academico', 'Abril 2025 - Septiembre 2025')
            ''')
            
            # ===== CREAR ACTIVIDADES COMPLEMENTARIAS POR DEFECTO =====
            # Estas SÍ se mantienen porque son datos de catálogo, no usuarios
            actividades_default = [
                ('T/AES', 'TUTORIAS/ACOMPAÑAMIENTO ESTUDIANTIL'),
                ('T/PPP', 'TUTORIAS/PRÁCTICAS PREPROFESIONALES'),
                ('T/VIC', 'TUTORIAS/VINCULACIÓN'),
                ('T/TIC', 'TUTORIAS/TRABAJO INTEGRADOR CURRICULAR'),
                ('INV', 'Investigación'),
                ('PCD', 'Planificación de clases'),
                ('CED', 'Calificación de evaluaciones y deberes'),
                ('EMD', 'Elaboración de material e insumos didácticos'),
                ('GAD', 'Gestión administrativa Docente'),
                ('CC', 'Coordinación de carrera'),
                ('CE', 'Coordinación estratégica')
            ]
            
            for codigo, descripcion in actividades_default:
                c.execute('SELECT id FROM actividades_complementarias WHERE codigo = ?', (codigo,))
                if c.fetchone() is None:
                    c.execute('''
                        INSERT INTO actividades_complementarias (codigo, descripcion, creado_por)
                        VALUES (?, ?, NULL)
                    ''', (codigo, descripcion))
                    log_action('admin', 'ACTIVIDAD_DEFAULT_CREADA', 
                               f'Actividad complementaria por defecto creada: {codigo}',
                               extra_data={'codigo': codigo, 'descripcion': descripcion})
            
            # ===== NO SE CREAN USUARIOS AQUÍ =====
            # Los usuarios se crean mediante setup_usuarios.py
            log_action('general', 'BD_ESTRUCTURA_CREADA', 
                       'Estructura de base de datos creada (sin usuarios por defecto)')
    
    try:
        execute_with_retry(_init)
        log_action('general', 'BD_INICIALIZADA', 'Base de datos inicializada correctamente')
        limpiar_archivos_huerfanos()
    except Exception as e:
        log_error_with_traceback('general', 'ERROR_INIT_BD', e)
        raise

# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verificar_password(password, password_hash):
    return hashlib.sha256(password.encode()).hexdigest() == password_hash

def convertir_hora_a_minutos(hora_str):
    try:
        partes = hora_str.split(':')
        return int(partes[0]) * 60 + int(partes[1])
    except:
        return 0

def obtener_actividades_complementarias():
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT codigo, descripcion
                FROM actividades_complementarias
                ORDER BY codigo
            ''')
            return {row['codigo']: row['descripcion'] for row in c.fetchall()}
    
    return execute_with_retry(_obtener)

def obtener_limites_actividades(usuario_id):
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT codigo_actividad, horas_asignadas
                FROM asignacion_actividades
                WHERE usuario_id = ?
            ''', (usuario_id,))
            return {row['codigo_actividad']: row['horas_asignadas'] for row in c.fetchall()}
    
    return execute_with_retry(_obtener)

def calcular_horas_por_dia(horario_data):
    horas_por_dia = {}
    
    for profesor in horario_data.get('profesores', []):
        for asignacion in profesor.get('horario', []):
            dia_id = asignacion.get('dia_id')
            if dia_id:
                horas_por_dia[dia_id] = horas_por_dia.get(dia_id, 0) + 1
        
        for actividad in profesor.get('actividades_complementarias', []):
            dia_id = actividad.get('dia_id')
            if dia_id:
                horas_por_dia[dia_id] = horas_por_dia.get(dia_id, 0) + 1
    
    return horas_por_dia

def validar_horas_actividades(horario_data, usuario_id):
    limites = obtener_limites_actividades(usuario_id)
    horas_usadas = {}
    for profesor in horario_data.get('profesores', []):
        actividades = profesor.get('actividades_complementarias', [])
        for act in actividades:
            codigo = act.get('codigo', '')
            if codigo:
                horas_usadas[codigo] = horas_usadas.get(codigo, 0) + 1
    
    errores = []
    
    for codigo, horas_usadas_valor in horas_usadas.items():
        limite = limites.get(codigo, 0)
        if limite == 0:
            errores.append(f"{codigo}: Sin horas asignadas")
        elif horas_usadas_valor > limite:
            errores.append(f"{codigo}: Excede límite ({horas_usadas_valor}/{limite}h)")
        elif horas_usadas_valor < limite:
            errores.append(f"{codigo}: Faltan {limite - horas_usadas_valor}h (debe usar {limite}h)")
    
    for codigo, limite in limites.items():
        if limite > 0 and codigo not in horas_usadas:
            errores.append(f"{codigo}: Debe agregar {limite}h al horario")
    
    for profesor in horario_data.get('profesores', []):
        actividades = profesor.get('actividades_complementarias', [])
        for act in actividades:
            if act.get('codigo') == 'T/AES':
                periodo_id = str(act.get('periodo_id', ''))
                if periodo_id not in PERIODOS_VALIDOS_TAES:
                    errores.append(f"T/AES en período inválido ({periodo_id}). Solo períodos 6,7,9,10")
    
    horas_por_dia = calcular_horas_por_dia(horario_data)
    for dia_id, total_horas in horas_por_dia.items():
        if total_horas > HORAS_MAXIMAS_POR_DIA:
            dias_nombres = {d['id']: d.get('name', d.get('short', str(d['id']))) 
                          for d in horario_data.get('dias', [])}
            dia_nombre = dias_nombres.get(dia_id, dia_id)
            errores.append(f"{dia_nombre}: Excede límite de {HORAS_MAXIMAS_POR_DIA}h (tiene {total_horas}h)")
    
    return errores

def obtener_ciclo_academico():
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT valor FROM configuracion WHERE clave = ?', ('ciclo_academico',))
            row = c.fetchone()
            return row['valor'] if row else 'Sin definir'
    
    return execute_with_retry(_obtener)

def procesar_horario_para_visualizacion(horario_data):
    horario = copy.deepcopy(horario_data)
    
    class_colors = {}
    color_index = 1
    
    for profesor in horario['profesores']:
        horario_dict = {}
        for asignacion in profesor['horario']:
            key = (asignacion['dia_id'], asignacion['periodo_id'])
            horario_dict[key] = asignacion
        
        actividades_dict = {}
        if 'actividades_complementarias' in profesor:
            for act in profesor['actividades_complementarias']:
                key = (act['dia_id'], act['periodo_id'])
                actividades_dict[key] = act
        
        dias_con_clases = set()
        for asignacion in profesor['horario']:
            dias_con_clases.add(asignacion['dia_id'])
        
        matriz_procesada = []
        
        for dia in horario['dias']:
            fila = {
                'dia': dia,
                'celdas': [],
                'dia_tiene_clases': dia['id'] in dias_con_clases
            }
            
            periodos = horario['periodos']
            period_idx = 0
            periods_to_skip = set()
            
            while period_idx < len(periodos):
                if period_idx in periods_to_skip:
                    period_idx += 1
                    continue
                
                periodo = periodos[period_idx]
                key = (dia['id'], periodo['id'])
                
                minutos_inicio = convertir_hora_a_minutos(periodo.get('starttime', '00:00'))
                permite_taes = False
                
                if dia['id'] in dias_con_clases and key not in horario_dict and key not in actividades_dict:
                    if periodo['id'] in PERIODOS_VALIDOS_TAES:
                        permite_taes = True
                
                if key in actividades_dict:
                    actividad = actividades_dict[key]
                    codigo_actividad = actividad['codigo']
                    
                    colspan = 1
                    for next_idx in range(period_idx + 1, len(periodos)):
                        next_periodo = periodos[next_idx]
                        next_key = (dia['id'], next_periodo['id'])
                        
                        if next_key in actividades_dict:
                            next_actividad = actividades_dict[next_key]
                            if next_actividad['codigo'] == codigo_actividad:
                                colspan += 1
                                periods_to_skip.add(next_idx)
                            else:
                                break
                        else:
                            break
                    
                    fila['celdas'].append({
                        'tipo': 'actividad',
                        'colspan': colspan,
                        'codigo': codigo_actividad,
                        'es_taes': actividad.get('es_taes', False),
                        'dia_id': dia['id'],
                        'periodo_id': periodo['id']
                    })
                elif key in horario_dict:
                    asignacion = horario_dict[key]
                    clase_nombre = asignacion['clase']['nombre_corto'] if asignacion['clase'] else ''
                    materia_id = asignacion['materia']['id'] if asignacion['materia'] else ''
                    materia_nombre = asignacion['materia']['nombre_corto'] if asignacion['materia'] else ''
                    
                    colspan = 1
                    for next_idx in range(period_idx + 1, len(periodos)):
                        next_periodo = periodos[next_idx]
                        next_key = (dia['id'], next_periodo['id'])
                        
                        if next_key in horario_dict:
                            next_asignacion = horario_dict[next_key]
                            next_clase_nombre = next_asignacion['clase']['nombre_corto'] if next_asignacion['clase'] else ''
                            next_materia_id = next_asignacion['materia']['id'] if next_asignacion['materia'] else ''
                            
                            if next_materia_id == materia_id and next_clase_nombre == clase_nombre:
                                colspan += 1
                                periods_to_skip.add(next_idx)
                            else:
                                break
                        else:
                            break
                    
                    if clase_nombre and clase_nombre not in class_colors:
                        class_colors[clase_nombre] = f"color-{color_index}"
                        color_index = (color_index % 8) + 1
                    
                    color_class = class_colors.get(clase_nombre, 'color-1') if clase_nombre else 'color-complementaria'
                    
                    fila['celdas'].append({
                        'tipo': 'clase',
                        'colspan': colspan,
                        'color': color_class,
                        'materia': materia_nombre,
                        'clase': clase_nombre,
                        'permite_taes': False,
                        'dia_id': dia['id'],
                        'periodo_id': periodo['id']
                    })
                else:
                    fila['celdas'].append({
                        'tipo': 'vacio',
                        'colspan': 1,
                        'permite_taes': permite_taes,
                        'dia_id': dia['id'],
                        'periodo_id': periodo['id']
                    })
                
                period_idx += 1
            
            matriz_procesada.append(fila)
        
        profesor['matriz_procesada'] = matriz_procesada
    
    return horario

# ============================================================================
# DECORADORES
# ============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            log_action('auth', 'ACCESO_DENEGADO', 
                       f'Intento de acceso sin autenticación a: {request.endpoint}',
                       level='warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'usuario_id' not in session:
                log_action('auth', 'ACCESO_DENEGADO', 
                           f'Intento de acceso sin autenticación a: {request.endpoint}',
                           level='warning')
                return redirect(url_for('login'))
            if session.get('rol') not in roles:
                log_action('auth', 'ACCESO_DENEGADO_ROL', 
                           f'Intento de acceso con rol insuficiente a: {request.endpoint}',
                           level='warning',
                           extra_data={'roles_requeridos': ','.join(roles)})
                flash('No tienes permisos para acceder a esta sección', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# RUTAS - AUTENTICACIÓN
# ============================================================================

@app.route('/')
def index():
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario')
        password = request.form.get('password')
        
        def _login():
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('SELECT * FROM usuarios WHERE usuario = ? AND activo = 1', (usuario,))
                return c.fetchone()
        
        try:
            user = execute_with_retry(_login)
            
            if user and verificar_password(password, user['password']):
                session.permanent = True
                session['usuario_id'] = user['id']
                session['usuario'] = user['usuario']
                session['nombre'] = user['nombre']
                session['cargo'] = user['cargo']
                session['rol'] = user['rol']
                
                log_action('auth', 'LOGIN_EXITOSO', 
                           f'Inicio de sesión exitoso',
                           extra_data={'usuario_id': user['id'], 'rol': user['rol']})
                
                flash('Inicio de sesión exitoso', 'success')
                return redirect(url_for('dashboard'))
            else:
                log_action('auth', 'LOGIN_FALLIDO', 
                           f'Intento de login fallido para usuario: {usuario}',
                           level='warning',
                           extra_data={'usuario_intentado': usuario})
                flash('Usuario o contraseña incorrectos', 'error')
        except Exception as e:
            log_error_with_traceback('auth', 'ERROR_LOGIN', e)
            flash('Error al procesar login. Intente nuevamente.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    usuario = session.get('usuario', 'DESCONOCIDO')
    log_action('auth', 'LOGOUT', f'Cierre de sesión', extra_data={'usuario': usuario})
    session.clear()
    return redirect(url_for('login') + '?logout=success')

@app.route('/cambiar_password', methods=['GET', 'POST'])
@login_required
def cambiar_password():
    if request.method == 'POST':
        data = request.get_json()
        password_actual = data.get('password_actual')
        password_nueva = data.get('password_nueva')
        password_confirmar = data.get('password_confirmar')
        
        if not password_actual or not password_nueva or not password_confirmar:
            return jsonify({'error': 'Todos los campos son obligatorios'}), 400
        
        if password_nueva != password_confirmar:
            return jsonify({'error': 'Las contraseñas nuevas no coinciden'}), 400
        
        if len(password_nueva) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        def _cambiar():
            with get_db_connection(write_mode=True) as conn:
                c = conn.cursor()
                c.execute('SELECT password FROM usuarios WHERE id = ?', (session['usuario_id'],))
                user = c.fetchone()
                
                if not user or not verificar_password(password_actual, user['password']):
                    return False
                
                password_hash = hash_password(password_nueva)
                c.execute('UPDATE usuarios SET password = ? WHERE id = ?', 
                          (password_hash, session['usuario_id']))
                return True
        
        try:
            resultado = execute_with_retry(_cambiar)
            
            if not resultado:
                log_action('auth', 'CAMBIO_PASSWORD_FALLIDO', 
                           'Intento de cambio de contraseña con password actual incorrecta',
                           level='warning')
                return jsonify({'error': 'Contraseña actual incorrecta'}), 400
            
            log_action('auth', 'CAMBIO_PASSWORD_EXITOSO', 
                       'Contraseña cambiada exitosamente por el usuario')
            
            return jsonify({'success': True, 'message': 'Contraseña actualizada correctamente'})
        except Exception as e:
            log_error_with_traceback('auth', 'ERROR_CAMBIAR_PASSWORD', e)
            return jsonify({'error': 'Error al cambiar contraseña'}), 500
    
    return render_template('cambiar_password.html',
                         nombre=session.get('nombre'),
                         cargo=session.get('cargo'),
                         rol=session.get('rol'))

# ============================================================================
# RUTAS - DASHBOARD
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    rol = session.get('rol')
    
    log_action('general', 'ACCESO_DASHBOARD', f'Acceso al dashboard ({rol})')
    
    if rol == 'coordinador':
        return redirect(url_for('coordinador_dashboard'))
    elif rol == 'rectorado':
        return redirect(url_for('rectorado_dashboard'))
    else:
        limites = obtener_limites_actividades(session['usuario_id'])
        return render_template('dashboard.html', 
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'),
                             limites_actividades=limites)

# ============================================================================
# RUTAS - HORARIOS (DOCENTES)
# ============================================================================

@app.route('/upload', methods=['POST'])
@role_required(['docente'])
def upload_horario():
    if 'horario' not in request.files:
        return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
    
    file = request.files['horario']
    
    if file.filename == '':
        return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
    
    if not file.filename.endswith('.hored'):
        return jsonify({'error': 'Solo se permiten archivos .hored'}), 400
    
    try:
        contenido = file.read().decode('utf-8')
        horario_data = json.loads(contenido)
        
        if horario_data.get('formato') != 'Horario Editable - aSc TimeTables':
            return jsonify({'error': 'Formato de archivo no válido'}), 400
        
        def _guardar():
            with get_db_connection(write_mode=True) as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO horarios (usuario_id, nombre_archivo, contenido_json, estado)
                    VALUES (?, ?, ?, 'borrador')
                ''', (session['usuario_id'], secure_filename(file.filename), json.dumps(horario_data)))
                return c.lastrowid
        
        horario_id = execute_with_retry(_guardar)
        
        guardar_archivo_horario(horario_id, horario_data)
        
        session['horario_actual_id'] = horario_id
        
        log_action('horarios', 'HORARIO_CARGADO', 
                   f'Horario cargado exitosamente: {file.filename}',
                   extra_data={
                       'horario_id': horario_id,
                       'nombre_archivo': file.filename,
                       'num_profesores': len(horario_data.get('profesores', [])),
                       'tamaño_bytes': len(contenido)
                   })
        
        return jsonify({
            'success': True,
            'message': 'Horario cargado correctamente',
            'horario_id': horario_id,
            'profesores': len(horario_data.get('profesores', []))
        })
    
    except json.JSONDecodeError as e:
        log_error_with_traceback('horarios', 'UPLOAD_JSON_ERROR', e,
                                extra_data={'archivo': file.filename})
        return jsonify({'error': 'Archivo JSON inválido'}), 400
    except Exception as e:
        log_error_with_traceback('horarios', 'UPLOAD_ERROR', e,
                                extra_data={'archivo': file.filename})
        return jsonify({'error': f'Error al procesar archivo: {str(e)}'}), 500

@app.route('/visualizar')
@role_required(['docente'])
def visualizar_horario():
    horario_id = request.args.get('id', session.get('horario_actual_id'))
    
    if not horario_id:
        flash('No hay horario seleccionado', 'warning')
        return redirect(url_for('dashboard'))
    
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM horarios WHERE id = ? AND usuario_id = ?', (horario_id, session['usuario_id']))
            horario_row = c.fetchone()
            
            if not horario_row:
                return None, None
            
            horario_data = json.loads(horario_row['contenido_json'])
            
            c.execute('''
                SELECT o.*, u.nombre as revisor_nombre, u.rol as revisor_rol
                FROM observaciones o
                JOIN usuarios u ON o.revisor_id = u.id
                WHERE o.horario_id = ? AND o.activa = 1
                ORDER BY o.fecha_observacion DESC
            ''', (horario_id,))
            observaciones = c.fetchall()
            
            dias_nombres = {}
            for dia in horario_data.get('dias', []):
                dias_nombres[dia['id']] = dia.get('name', dia.get('short', 'Día'))
            
            observaciones_list = []
            for obs in observaciones:
                c.execute('SELECT * FROM observaciones_especificas WHERE observacion_id = ?', (obs['id'],))
                especificas = c.fetchall()
                
                especificas_legibles = []
                for esp in especificas:
                    dia_nombre = dias_nombres.get(esp['dia_id'], esp['dia_id'])
                    especificas_legibles.append({
                        'dia_id': esp['dia_id'],
                        'dia_nombre': dia_nombre,
                        'periodo_id': esp['periodo_id'],
                        'comentario': esp['comentario']
                    })
                
                observaciones_list.append({
                    'id': obs['id'],
                    'tipo_revisor': obs['tipo_revisor'],
                    'revisor_nombre': obs['revisor_nombre'],
                    'observacion_general': obs['observacion_general'],
                    'fecha': obs['fecha_observacion'],
                    'especificas': especificas_legibles
                })
            
            return horario_row, (horario_data, observaciones_list)
    
    try:
        horario_row, data = execute_with_retry(_obtener)
        
        if not horario_row:
            flash('Horario no encontrado', 'error')
            return redirect(url_for('dashboard'))
        
        horario_data, observaciones_list = data
        
        limites = obtener_limites_actividades(session['usuario_id'])
        actividades_disponibles = obtener_actividades_complementarias()
        
        horario_procesado = procesar_horario_para_visualizacion(horario_data)
        
        horas_por_dia = {}
        for dia in horario_data.get('dias', []):
            dia_id = dia['id']
            horas_ocupadas = 0
            
            for profesor in horario_data.get('profesores', []):
                for asignacion in profesor.get('horario', []):
                    if asignacion.get('dia_id') == dia_id:
                        horas_ocupadas += 1
                
                for actividad in profesor.get('actividades_complementarias', []):
                    if actividad.get('dia_id') == dia_id:
                        horas_ocupadas += 1
            
            horas_por_dia[dia_id] = {
                'ocupadas': horas_ocupadas,
                'disponibles': max(0, HORAS_MAXIMAS_POR_DIA - horas_ocupadas),
                'total': HORAS_MAXIMAS_POR_DIA
            }
        
        log_action('horarios', 'VISUALIZAR', 
                   f'Visualización de horario',
                   extra_data={'horario_id': horario_id, 'estado': horario_row['estado']})
        
        return render_template('visualizar.html',
                             horario=horario_procesado,
                             horario_id=horario_id,
                             estado=horario_row['estado'],
                             observaciones=observaciones_list,
                             limites_actividades=limites,
                             actividades_disponibles=actividades_disponibles,
                             horas_por_dia=horas_por_dia,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_VISUALIZAR', e)
        flash('Error al cargar horario', 'error')
        return redirect(url_for('dashboard'))

@app.route('/guardar_actividades/<int:horario_id>', methods=['POST'])
@role_required(['docente'])
def guardar_actividades(horario_id):
    def _guardar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT * FROM horarios WHERE id = ? AND usuario_id = ?', (horario_id, session['usuario_id']))
            horario = c.fetchone()
            
            if not horario:
                return None
            
            horario_data = json.loads(horario['contenido_json'])
            data = request.get_json()
            actividades = data.get('actividades', [])
            
            horas_por_dia = {}
            
            for profesor in horario_data.get('profesores', []):
                for asignacion in profesor.get('horario', []):
                    dia_id = asignacion.get('dia_id')
                    if dia_id:
                        horas_por_dia[dia_id] = horas_por_dia.get(dia_id, 0) + 1
            
            for act in actividades:
                dia_id = act.get('dia_id')
                if dia_id:
                    horas_por_dia[dia_id] = horas_por_dia.get(dia_id, 0) + 1
            
            for dia_id, total_horas in horas_por_dia.items():
                if total_horas > HORAS_MAXIMAS_POR_DIA:
                    dias_nombres = {d['id']: d.get('name', d.get('short', str(d['id']))) 
                                  for d in horario_data.get('dias', [])}
                    dia_nombre = dias_nombres.get(dia_id, dia_id)
                    return {'error': f'{dia_nombre} excede {HORAS_MAXIMAS_POR_DIA}h (tiene {total_horas}h)'}
            
            if horario_data.get('profesores'):
                horario_data['profesores'][0]['actividades_complementarias'] = actividades
            
            c.execute('UPDATE horarios SET contenido_json = ? WHERE id = ?', 
                      (json.dumps(horario_data), horario_id))
            
            return {'success': True, 'horario_data': horario_data}
    
    try:
        resultado = execute_with_retry(_guardar)
        
        if resultado is None:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        if 'error' in resultado:
            log_action('horarios', 'GUARDAR_ACTIVIDADES_ERROR', 
                       f'Intento de exceder límite de horas',
                       level='warning',
                       extra_data={'horario_id': horario_id})
            return jsonify(resultado), 400
        
        guardar_archivo_horario(horario_id, resultado['horario_data'])
        
        log_action('horarios', 'ACTIVIDADES_GUARDADAS', 
                   f'Actividades complementarias guardadas',
                   extra_data={'horario_id': horario_id})
        
        return jsonify({'success': True})
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_GUARDAR_ACTIVIDADES', e)
        return jsonify({'error': 'Error al guardar actividades'}), 500

@app.route('/enviar_revision/<int:horario_id>', methods=['POST'])
@role_required(['docente'])
def enviar_revision(horario_id):
    def _enviar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT * FROM horarios WHERE id = ? AND usuario_id = ?', (horario_id, session['usuario_id']))
            horario = c.fetchone()
            
            if not horario:
                return None
            
            horario_data = json.loads(horario['contenido_json'])
            
            errores = validar_horas_actividades(horario_data, session['usuario_id'])
            
            if errores:
                return {'errores': errores}
            
            estado_actual = horario['estado']
            nuevo_estado = 'revision_coordinador'
            
            if estado_actual == 'rechazado_rectorado':
                nuevo_estado = 'revision_rectorado'
            
            c.execute('''
                UPDATE horarios 
                SET estado = ?, fecha_envio_revision = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (nuevo_estado, horario_id))
            
            return {'success': True, 'nuevo_estado': nuevo_estado}
    
    try:
        resultado = execute_with_retry(_enviar)
        
        if resultado is None:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        if 'errores' in resultado:
            log_action('horarios', 'ENVIAR_REVISION_ERROR', 
                       f'Validación fallida al enviar a revisión',
                       level='warning',
                       extra_data={'horario_id': horario_id, 'errores': len(resultado['errores'])})
            return jsonify({
                'error': 'Errores de validación detectados',
                'errores': resultado['errores']
            }), 400
        
        destino = 'Coordinador' if resultado['nuevo_estado'] == 'revision_coordinador' else 'Rectorado'
        
        log_action('horarios', 'ENVIAR_REVISION', 
                   f'Horario enviado a revisión',
                   extra_data={'horario_id': horario_id, 'destino': destino, 'estado': resultado['nuevo_estado']})
        
        return jsonify({
            'success': True,
            'message': f'Enviado a {destino}'
        })
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_ENVIAR_REVISION', e)
        return jsonify({'error': 'Error al enviar a revisión'}), 500

@app.route('/bandeja')
@role_required(['docente'])
def bandeja_docente():
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT h.*, 
                       uc.nombre as coordinador_nombre,
                       ur.nombre as rectorado_nombre
                FROM horarios h
                LEFT JOIN usuarios uc ON h.revisor_coordinador_id = uc.id
                LEFT JOIN usuarios ur ON h.revisor_rectorado_id = ur.id
                WHERE h.usuario_id = ?
                ORDER BY h.fecha_carga DESC
            ''', (session['usuario_id'],))
            return c.fetchall()
    
    try:
        horarios = execute_with_retry(_obtener)
        
        log_action('horarios', 'ACCESO_BANDEJA', 
                   f'Acceso a bandeja de horarios',
                   extra_data={'num_horarios': len(horarios)})
        
        return render_template('bandeja_docente.html',
                             horarios=horarios,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_BANDEJA', e)
        flash('Error al cargar bandeja', 'error')
        return redirect(url_for('dashboard'))

@app.route('/eliminar_horario/<int:horario_id>', methods=['DELETE'])
@role_required(['docente'])
def eliminar_horario(horario_id):
    def _eliminar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT * FROM horarios WHERE id = ? AND usuario_id = ?', (horario_id, session['usuario_id']))
            horario = c.fetchone()
            
            if not horario:
                return None
            
            estado_anterior = horario['estado']
            nombre_archivo = horario['nombre_archivo']
            
            c.execute('''
                DELETE FROM observaciones_especificas 
                WHERE observacion_id IN (
                    SELECT id FROM observaciones WHERE horario_id = ?
                )
            ''', (horario_id,))
            
            c.execute('DELETE FROM observaciones WHERE horario_id = ?', (horario_id,))
            c.execute('DELETE FROM horarios WHERE id = ?', (horario_id,))
            
            return {'estado': estado_anterior, 'nombre': nombre_archivo}
    
    try:
        resultado = execute_with_retry(_eliminar)
        
        if resultado is None:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        eliminar_archivo_horario(horario_id)
        
        log_action('horarios', 'HORARIO_ELIMINADO', 
                   f'Horario eliminado exitosamente',
                   extra_data={
                       'horario_id': horario_id,
                       'estado': resultado['estado'],
                       'nombre_archivo': resultado['nombre']
                   })
        
        # Sin mensaje - solo éxito
        return jsonify({'success': True})
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_ELIMINAR_HORARIO', e)
        return jsonify({'error': 'Error al eliminar horario'}), 500

@app.route('/descargar_hored/<int:horario_id>')
@role_required(['docente'])
def descargar_hored(horario_id):
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM horarios WHERE id = ? AND usuario_id = ?', (horario_id, session['usuario_id']))
            return c.fetchone()
    
    try:
        horario = execute_with_retry(_obtener)
        
        if not horario:
            flash('Horario no encontrado', 'error')
            return redirect(url_for('bandeja_docente'))
        
        if horario['estado'] != 'aprobado':
            flash('Solo se pueden descargar horarios aprobados en formato .hored', 'warning')
            return redirect(url_for('bandeja_docente'))
        
        horario_data = json.loads(horario['contenido_json'])
        contenido = json.dumps(horario_data, ensure_ascii=False, indent=2)
        
        buffer = BytesIO()
        buffer.write(contenido.encode('utf-8'))
        buffer.seek(0)
        
        nombre_archivo = horario['nombre_archivo']
        if not nombre_archivo.endswith('.hored'):
            nombre_archivo += '.hored'
        
        log_action('horarios', 'DESCARGA_HORED', 
                   f'Descarga de archivo .hored',
                   extra_data={'horario_id': horario_id, 'nombre_archivo': nombre_archivo})
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=nombre_archivo,
            mimetype='application/json'
        )
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_DESCARGAR_HORED', e)
        flash('Error al descargar archivo', 'error')
        return redirect(url_for('bandeja_docente'))

# ============================================================================
# RUTAS - COORDINADOR
# ============================================================================

@app.route('/coordinador')
@role_required(['coordinador'])
def coordinador_dashboard():
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT h.*, u.nombre as docente_nombre, u.cargo as docente_cargo
                FROM horarios h
                JOIN usuarios u ON h.usuario_id = u.id
                WHERE h.estado = 'revision_coordinador'
                ORDER BY h.fecha_envio_revision ASC
            ''', ())
            return c.fetchall()
    
    try:
        horarios_pendientes = execute_with_retry(_obtener)
        
        log_action('admin', 'ACCESO_COORDINADOR', 
                   f'Acceso al dashboard de coordinador',
                   extra_data={'horarios_pendientes': len(horarios_pendientes)})
        
        return render_template('coordinador_dashboard.html',
                             horarios=horarios_pendientes,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_DASHBOARD_COORDINADOR', e)
        flash('Error al cargar dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/coordinador/actividades_complementarias', methods=['GET'])
@role_required(['coordinador'])
def listar_actividades_complementarias():
    def _listar():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT ac.id, ac.codigo, ac.descripcion, ac.fecha_creacion, ac.creado_por,
                       u.nombre as creador_nombre
                FROM actividades_complementarias ac
                LEFT JOIN usuarios u ON ac.creado_por = u.id
                ORDER BY ac.codigo
            ''')
            return c.fetchall()
    
    try:
        actividades = execute_with_retry(_listar)
        return jsonify({
            'actividades': [dict(act) for act in actividades]
        })
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_LISTAR_ACTIVIDADES', e)
        return jsonify({'error': 'Error al listar actividades'}), 500

@app.route('/api/actividades_complementarias', methods=['GET'])
@login_required
def api_actividades_complementarias():
    try:
        actividades = obtener_actividades_complementarias()
        return jsonify({
            'actividades': [{'codigo': k, 'descripcion': v} for k, v in actividades.items()]
        })
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_API_ACTIVIDADES', e)
        return jsonify({'error': 'Error al obtener actividades'}), 500

@app.route('/coordinador/actividades_complementarias/crear', methods=['POST'])
@role_required(['coordinador'])
def crear_actividad_complementaria():
    data = request.get_json()
    codigo = data.get('codigo', '').strip().upper()
    descripcion = data.get('descripcion', '').strip()
    
    if not codigo or not descripcion:
        return jsonify({'error': 'Código y descripción son obligatorios'}), 400
    
    if len(codigo) > 15:
        return jsonify({'error': 'El código no puede exceder 15 caracteres'}), 400
    
    def _crear():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT id FROM actividades_complementarias WHERE codigo = ?', (codigo,))
            if c.fetchone():
                return None
            
            c.execute('''
                INSERT INTO actividades_complementarias (codigo, descripcion, creado_por)
                VALUES (?, ?, ?)
            ''', (codigo, descripcion, session['usuario_id']))
            
            return c.lastrowid
    
    try:
        actividad_id = execute_with_retry(_crear)
        
        if actividad_id is None:
            return jsonify({'error': f'El código "{codigo}" ya existe. Usa otro código.'}), 400
        
        log_action('admin', 'ACTIVIDAD_CREADA', 
                   f'Actividad complementaria creada',
                   extra_data={'codigo': codigo, 'descripcion': descripcion})
        
        return jsonify({
            'success': True,
            'message': f'✓ Actividad "{codigo}" creada exitosamente',
            'id': actividad_id
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': f'El código "{codigo}" ya existe'}), 400
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_CREAR_ACTIVIDAD', e)
        return jsonify({'error': f'Error al crear: {str(e)}'}), 500

@app.route('/coordinador/actividades_complementarias/<int:actividad_id>', methods=['PUT'])
@role_required(['coordinador'])
def actualizar_actividad_complementaria(actividad_id):
    data = request.get_json()
    codigo_nuevo = data.get('codigo_nuevo', data.get('codigo', '')).strip().upper()
    descripcion = data.get('descripcion', '').strip()
    
    if not codigo_nuevo or not descripcion:
        return jsonify({'error': 'Código y descripción son obligatorios'}), 400
    
    if len(codigo_nuevo) > 15:
        return jsonify({'error': 'El código no puede exceder 15 caracteres'}), 400
    
    def _actualizar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT codigo FROM actividades_complementarias WHERE id = ?', (actividad_id,))
            actividad = c.fetchone()
            
            if not actividad:
                return None
            
            codigo_antiguo = actividad['codigo']
            
            if codigo_nuevo != codigo_antiguo:
                c.execute('''
                    SELECT id FROM actividades_complementarias 
                    WHERE codigo = ? AND id != ?
                ''', (codigo_nuevo, actividad_id))
                
                if c.fetchone():
                    return {'error': f'El código "{codigo_nuevo}" ya está en uso por otra actividad'}
                
                c.execute('''
                    UPDATE asignacion_actividades 
                    SET codigo_actividad = ? 
                    WHERE codigo_actividad = ?
                ''', (codigo_nuevo, codigo_antiguo))
            
            c.execute('''
                UPDATE actividades_complementarias
                SET codigo = ?, descripcion = ?
                WHERE id = ?
            ''', (codigo_nuevo, descripcion, actividad_id))
            
            return {'codigo_antiguo': codigo_antiguo, 'codigo_nuevo': codigo_nuevo}
    
    try:
        resultado = execute_with_retry(_actualizar)
        
        if resultado is None:
            return jsonify({'error': 'Actividad no encontrada'}), 404
        
        if 'error' in resultado:
            return jsonify(resultado), 400
        
        mensaje = f'✓ Actividad actualizada exitosamente'
        if resultado['codigo_nuevo'] != resultado['codigo_antiguo']:
            mensaje = f'✓ Actividad actualizada: "{resultado["codigo_antiguo"]}" → "{resultado["codigo_nuevo"]}"'
            log_action('admin', 'ACTIVIDAD_ACTUALIZADA', 
                       f'Actividad complementaria actualizada',
                       extra_data={
                           'codigo_antiguo': resultado['codigo_antiguo'],
                           'codigo_nuevo': resultado['codigo_nuevo'],
                           'descripcion': descripcion
                       })
        else:
            log_action('admin', 'ACTIVIDAD_ACTUALIZADA', 
                       f'Actividad complementaria actualizada',
                       extra_data={'codigo': codigo_nuevo, 'descripcion': descripcion})
        
        return jsonify({
            'success': True,
            'message': mensaje
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': f'El código "{codigo_nuevo}" ya existe'}), 400
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_ACTUALIZAR_ACTIVIDAD', e)
        return jsonify({'error': f'Error al actualizar: {str(e)}'}), 500

@app.route('/coordinador/actividades_complementarias/<int:actividad_id>', methods=['DELETE'])
@role_required(['coordinador'])
def eliminar_actividad_complementaria(actividad_id):
    def _eliminar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT codigo FROM actividades_complementarias WHERE id = ?', (actividad_id,))
            actividad = c.fetchone()
            
            if not actividad:
                return None
            
            codigo = actividad['codigo']
            
            c.execute('''
                SELECT u.nombre, aa.horas_asignadas
                FROM asignacion_actividades aa
                JOIN usuarios u ON aa.usuario_id = u.id
                WHERE aa.codigo_actividad = ? AND aa.horas_asignadas > 0
                ORDER BY u.nombre
            ''', (codigo,))
            
            asignaciones_activas = c.fetchall()
            
            if asignaciones_activas:
                docentes_lista = []
                total_horas = 0
                for asig in asignaciones_activas:
                    docentes_lista.append(f"{asig['nombre']} ({asig['horas_asignadas']}h)")
                    total_horas += asig['horas_asignadas']
                
                mensaje_error = f'No se puede eliminar la actividad "{codigo}" porque está asignada a:<br><br>'
                mensaje_error += '<br>'.join(docentes_lista)
                mensaje_error += f'<br><br><strong>Total: {total_horas} horas asignadas</strong>'
                mensaje_error += '<br><br>Ve a la pestaña "Asignar Horas por Docente" y pon todas las horas en 0, luego guarda los cambios.'
                
                return {'error': mensaje_error}
            
            c.execute('DELETE FROM asignacion_actividades WHERE codigo_actividad = ?', (codigo,))
            c.execute('DELETE FROM actividades_complementarias WHERE id = ?', (actividad_id,))
            
            filas_eliminadas = c.rowcount
            
            return {'success': True, 'codigo': codigo, 'filas': filas_eliminadas}
    
    try:
        resultado = execute_with_retry(_eliminar)
        
        if resultado is None:
            return jsonify({'error': 'Actividad no encontrada'}), 404
        
        if 'error' in resultado:
            log_action('admin', 'ELIMINAR_ACTIVIDAD_ERROR', 
                       f'Intento de eliminar actividad con asignaciones activas',
                       level='warning')
            return jsonify(resultado), 400
        
        if resultado['filas'] > 0:
            log_action('admin', 'ACTIVIDAD_ELIMINADA', 
                       f'Actividad complementaria eliminada',
                       extra_data={'codigo': resultado['codigo']})
            return jsonify({
                'success': True,
                'message': f'✓ Actividad "{resultado["codigo"]}" eliminada permanentemente'
            })
        else:
            return jsonify({'error': 'No se pudo eliminar la actividad'}), 500
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_ELIMINAR_ACTIVIDAD', e)
        return jsonify({'error': f'Error al eliminar: {str(e)}'}), 500

# ============================================================================
# RUTAS - COORDINADOR (CONTINUACIÓN)
# ============================================================================

@app.route('/coordinador/gestionar_actividades', methods=['GET', 'POST'])
@role_required(['coordinador'])
def gestionar_actividades():
    if request.method == 'POST':
        data = request.get_json()
        usuario_id = data.get('usuario_id')
        asignaciones = data.get('asignaciones', {})
        
        if not usuario_id:
            return jsonify({'error': 'ID de usuario no proporcionado'}), 400
        
        def _guardar():
            with get_db_connection(write_mode=True) as conn:
                c = conn.cursor()
                
                c.execute('SELECT id, nombre FROM usuarios WHERE id = ? AND rol = "docente"', (usuario_id,))
                docente = c.fetchone()
                
                if not docente:
                    return None
                
                c.execute('DELETE FROM asignacion_actividades WHERE usuario_id = ?', (usuario_id,))
                
                horas_totales = 0
                for codigo, horas in asignaciones.items():
                    horas_int = int(horas)
                    if horas_int >= 0:
                        c.execute('''
                            INSERT INTO asignacion_actividades (usuario_id, codigo_actividad, horas_asignadas, asignado_por)
                            VALUES (?, ?, ?, ?)
                        ''', (usuario_id, codigo, horas_int, session['usuario_id']))
                        horas_totales += horas_int
                
                return {'docente': docente, 'horas_totales': horas_totales}
        
        try:
            resultado = execute_with_retry(_guardar)
            
            if resultado is None:
                return jsonify({'error': 'Docente no encontrado'}), 404
            
            log_action('admin', 'ASIGNACIONES_GUARDADAS', 
                       f'Asignaciones de actividades guardadas',
                       extra_data={
                           'docente_id': usuario_id,
                           'docente_nombre': resultado['docente']['nombre'],
                           'total_horas': resultado['horas_totales'],
                           'actividades': len([h for h in asignaciones.values() if int(h) > 0])
                       })
            
            return jsonify({
                'success': True, 
                'message': f'Asignaciones guardadas para {resultado["docente"]["nombre"]} ({resultado["horas_totales"]} horas totales)',
                'total_horas': resultado['horas_totales']
            })
        except Exception as e:
            log_error_with_traceback('admin', 'ERROR_GUARDAR_ASIGNACIONES', e)
            return jsonify({'error': f'Error al guardar: {str(e)}'}), 500
    
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, usuario, nombre, cargo
                FROM usuarios
                WHERE rol = 'docente' AND activo = 1
                ORDER BY nombre
            ''')
            docentes = c.fetchall()
            
            docentes_list = []
            for docente in docentes:
                c.execute('''
                    SELECT codigo_actividad, horas_asignadas
                    FROM asignacion_actividades
                    WHERE usuario_id = ?
                ''', (docente['id'],))
                asignaciones = {row['codigo_actividad']: row['horas_asignadas'] for row in c.fetchall()}
                
                docentes_list.append({
                    'id': docente['id'],
                    'usuario': docente['usuario'],
                    'nombre': docente['nombre'],
                    'cargo': docente['cargo'],
                    'asignaciones': asignaciones
                })
            
            return docentes_list
    
    try:
        docentes_list = execute_with_retry(_obtener)
        actividades = obtener_actividades_complementarias()
        
        return render_template('gestionar_actividades.html',
                             docentes=docentes_list,
                             actividades=actividades,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_GESTIONAR_ACTIVIDADES', e)
        flash('Error al cargar página', 'error')
        return redirect(url_for('coordinador_dashboard'))

@app.route('/coordinador/obtener_docentes_asignaciones', methods=['GET'])
@role_required(['coordinador'])
def obtener_docentes_asignaciones():
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            
            c.execute('''
                SELECT id, usuario, nombre, cargo
                FROM usuarios
                WHERE rol = 'docente' AND activo = 1
                ORDER BY nombre
            ''')
            docentes = c.fetchall()
            
            docentes_list = []
            for docente in docentes:
                c.execute('''
                    SELECT codigo_actividad, horas_asignadas
                    FROM asignacion_actividades
                    WHERE usuario_id = ?
                ''', (docente['id'],))
                
                asignaciones_rows = c.fetchall()
                asignaciones = {row['codigo_actividad']: row['horas_asignadas'] for row in asignaciones_rows}
                
                docentes_list.append({
                    'id': docente['id'],
                    'usuario': docente['usuario'],
                    'nombre': docente['nombre'],
                    'cargo': docente['cargo'],
                    'asignaciones': asignaciones
                })
            
            return docentes_list
    
    try:
        docentes_list = execute_with_retry(_obtener)
        return jsonify({
            'success': True,
            'docentes': docentes_list
        })
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_OBTENER_DOCENTES', e)
        return jsonify({
            'success': False,
            'error': f'Error al obtener docentes: {str(e)}'
        }), 500

@app.route('/coordinador/configurar_ciclo', methods=['GET', 'POST'])
@role_required(['coordinador'])
def configurar_ciclo():
    if request.method == 'POST':
        data = request.get_json()
        ciclo = data.get('ciclo_academico', '')
        
        if not ciclo:
            return jsonify({'error': 'El ciclo académico no puede estar vacío'}), 400
        
        def _guardar():
            with get_db_connection(write_mode=True) as conn:
                c = conn.cursor()
                
                c.execute('SELECT valor FROM configuracion WHERE clave = ?', ('ciclo_academico',))
                ciclo_anterior = c.fetchone()
                ciclo_anterior_valor = ciclo_anterior['valor'] if ciclo_anterior else 'Sin definir'
                
                c.execute('''
                    INSERT OR REPLACE INTO configuracion (clave, valor, fecha_modificacion)
                    VALUES ('ciclo_academico', ?, CURRENT_TIMESTAMP)
                ''', (ciclo,))
                
                return ciclo_anterior_valor
        
        try:
            ciclo_anterior = execute_with_retry(_guardar)
            
            log_action('admin', 'CICLO_ACTUALIZADO', 
                       f'Ciclo académico actualizado',
                       extra_data={'anterior': ciclo_anterior, 'nuevo': ciclo})
            
            return jsonify({'success': True, 'message': 'Ciclo académico actualizado'})
        except Exception as e:
            log_error_with_traceback('admin', 'ERROR_ACTUALIZAR_CICLO', e)
            return jsonify({'error': 'Error al actualizar ciclo'}), 500
    
    ciclo_actual = obtener_ciclo_academico()
    return render_template('configurar_ciclo.html',
                         ciclo_actual=ciclo_actual,
                         nombre=session.get('nombre'),
                         cargo=session.get('cargo'),
                         rol=session.get('rol'))

@app.route('/coordinador/revisar/<int:horario_id>')
@role_required(['coordinador'])
def coordinador_revisar(horario_id):
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT h.*, u.nombre as docente_nombre, u.cargo as docente_cargo
                FROM horarios h
                JOIN usuarios u ON h.usuario_id = u.id
                WHERE h.id = ?
            ''', (horario_id,))
            horario_row = c.fetchone()
            
            if not horario_row:
                return None, None
            
            horario_data = json.loads(horario_row['contenido_json'])
            
            c.execute('''
                SELECT o.*, u.nombre as revisor_nombre, u.rol as revisor_rol
                FROM observaciones o
                JOIN usuarios u ON o.revisor_id = u.id
                WHERE o.horario_id = ? AND o.tipo_revisor = 'coordinador'
                ORDER BY o.fecha_observacion DESC
            ''', (horario_id,))
            observaciones = c.fetchall()
            
            historial_observaciones = []
            for obs in observaciones:
                c.execute('SELECT * FROM observaciones_especificas WHERE observacion_id = ?', (obs['id'],))
                especificas = c.fetchall()
                
                historial_observaciones.append({
                    'id': obs['id'],
                    'revisor_nombre': obs['revisor_nombre'],
                    'observacion_general': obs['observacion_general'],
                    'fecha': obs['fecha_observacion'],
                    'activa': obs['activa'],
                    'especificas': [dict(e) for e in especificas]
                })
            
            return horario_row, (horario_data, historial_observaciones)
    
    try:
        horario_row, data = execute_with_retry(_obtener)
        
        if not horario_row:
            flash('Horario no encontrado', 'error')
            return redirect(url_for('coordinador_dashboard'))
        
        horario_data, historial_observaciones = data
        horario_procesado = procesar_horario_para_visualizacion(horario_data)
        
        log_action('admin', 'REVISAR_HORARIO', 
                   f'Coordinador revisando horario',
                   extra_data={'horario_id': horario_id, 'docente': horario_row['docente_nombre']})
        
        return render_template('coordinador_revisar.html',
                             horario=horario_procesado,
                             horario_id=horario_id,
                             horario_info=horario_row,
                             historial_observaciones=historial_observaciones,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_REVISAR_COORDINADOR', e)
        flash('Error al cargar horario', 'error')
        return redirect(url_for('coordinador_dashboard'))

@app.route('/coordinador/guardar_observaciones/<int:horario_id>', methods=['POST'])
@role_required(['coordinador'])
def coordinador_guardar_observaciones(horario_id):
    data = request.get_json()
    
    def _guardar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('''
                INSERT INTO observaciones (horario_id, revisor_id, tipo_revisor, observacion_general)
                VALUES (?, ?, 'coordinador', ?)
            ''', (horario_id, session['usuario_id'], data.get('observacion_general', '')))
            
            observacion_id = c.lastrowid
            
            for obs_esp in data.get('observaciones_especificas', []):
                c.execute('''
                    INSERT INTO observaciones_especificas (observacion_id, dia_id, periodo_id, comentario)
                    VALUES (?, ?, ?, ?)
                ''', (observacion_id, obs_esp['dia_id'], obs_esp['periodo_id'], obs_esp['comentario']))
            
            return observacion_id
    
    try:
        observacion_id = execute_with_retry(_guardar)
        
        log_action('admin', 'OBSERVACIONES_GUARDADAS', 
                   f'Coordinador guardó observaciones',
                   extra_data={
                       'horario_id': horario_id,
                       'observacion_id': observacion_id,
                       'num_especificas': len(data.get('observaciones_especificas', []))
                   })
        
        return jsonify({'success': True, 'observacion_id': observacion_id})
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_GUARDAR_OBSERVACIONES', e)
        return jsonify({'error': 'Error al guardar observaciones'}), 500

@app.route('/coordinador/aprobar/<int:horario_id>', methods=['POST'])
@role_required(['coordinador'])
def coordinador_aprobar(horario_id):
    def _aprobar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT usuario_id FROM horarios WHERE id = ?', (horario_id,))
            horario = c.fetchone()
            
            if not horario:
                return None
            
            c.execute('''
                UPDATE horarios 
                SET estado = 'revision_rectorado', 
                    revisor_coordinador_id = ?,
                    fecha_revision_coordinador = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (session['usuario_id'], horario_id))
            
            return True
    
    try:
        resultado = execute_with_retry(_aprobar)
        
        if resultado is None:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        log_action('admin', 'HORARIO_APROBADO_COORDINADOR', 
                   f'Coordinador aprobó horario y envió a rectorado',
                   extra_data={'horario_id': horario_id})
        
        return jsonify({'success': True, 'message': 'Horario aprobado y enviado a Rectorado'})
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_APROBAR_COORDINADOR', e)
        return jsonify({'error': 'Error al aprobar horario'}), 500

@app.route('/coordinador/rechazar/<int:horario_id>', methods=['POST'])
@role_required(['coordinador'])
def coordinador_rechazar(horario_id):
    def _rechazar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('''
                UPDATE horarios 
                SET estado = 'rechazado_coordinador',
                    revisor_coordinador_id = ?,
                    fecha_revision_coordinador = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (session['usuario_id'], horario_id))
            
            return c.rowcount > 0
    
    try:
        resultado = execute_with_retry(_rechazar)
        
        if not resultado:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        log_action('admin', 'HORARIO_RECHAZADO_COORDINADOR', 
                   f'Coordinador rechazó horario',
                   extra_data={'horario_id': horario_id})
        
        return jsonify({'success': True, 'message': 'Horario rechazado y devuelto al docente'})
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_RECHAZAR_COORDINADOR', e)
        return jsonify({'error': 'Error al rechazar horario'}), 500

@app.route('/coordinador/crear_docente', methods=['GET', 'POST'])
@role_required(['coordinador'])
def crear_docente():
    if request.method == 'POST':
        data = request.get_json()
        
        def _crear():
            with get_db_connection(write_mode=True) as conn:
                c = conn.cursor()
                
                password_hash = hash_password(data['password'])
                c.execute('''
                    INSERT INTO usuarios (usuario, password, nombre, cargo, rol, creado_por)
                    VALUES (?, ?, ?, ?, 'docente', ?)
                ''', (data['usuario'], password_hash, data['nombre'], data['cargo'], session['usuario_id']))
                
                return c.lastrowid
        
        try:
            docente_id = execute_with_retry(_crear)
            
            log_action('admin', 'DOCENTE_CREADO', 
                       f'Docente creado',
                       extra_data={
                           'docente_id': docente_id,
                           'usuario': data['usuario'],
                           'nombre': data['nombre']
                       })
            
            return jsonify({'success': True, 'message': 'Docente creado exitosamente'})
        except sqlite3.IntegrityError:
            log_action('admin', 'ERROR_CREAR_DOCENTE', 
                       f'Intento de crear docente con usuario duplicado',
                       level='warning',
                       extra_data={'usuario': data['usuario']})
            return jsonify({'error': 'El nombre de usuario ya existe'}), 400
        except Exception as e:
            log_error_with_traceback('admin', 'ERROR_CREAR_DOCENTE', e)
            return jsonify({'error': str(e)}), 500
    
    def _listar():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, usuario, nombre, cargo, activo, fecha_creacion
                FROM usuarios
                WHERE rol = 'docente'
                ORDER BY fecha_creacion DESC
            ''')
            return c.fetchall()
    
    try:
        docentes = execute_with_retry(_listar)
        
        return render_template('crear_docente.html',
                             docentes=docentes,
                             usuario=session.get('usuario'),
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_LISTAR_DOCENTES', e)
        flash('Error al cargar página', 'error')
        return redirect(url_for('coordinador_dashboard'))

@app.route('/coordinador/eliminar_docente/<int:docente_id>', methods=['DELETE'])
@role_required(['coordinador'])
def eliminar_docente(docente_id):
    def _eliminar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT * FROM usuarios WHERE id = ? AND rol = "docente"', (docente_id,))
            docente = c.fetchone()
            
            if not docente:
                return None
            
            docente_nombre = docente['nombre']
            docente_usuario = docente['usuario']
            
            c.execute('SELECT id FROM horarios WHERE usuario_id = ?', (docente_id,))
            horarios = c.fetchall()
            
            for horario in horarios:
                horario_id = horario['id']
                eliminar_archivo_horario(horario_id)
                
                c.execute('''
                    DELETE FROM observaciones_especificas 
                    WHERE observacion_id IN (
                        SELECT id FROM observaciones WHERE horario_id = ?
                    )
                ''', (horario_id,))
                
                c.execute('DELETE FROM observaciones WHERE horario_id = ?', (horario_id,))
            
            c.execute('DELETE FROM horarios WHERE usuario_id = ?', (docente_id,))
            c.execute('DELETE FROM asignacion_actividades WHERE usuario_id = ?', (docente_id,))
            c.execute('DELETE FROM usuarios WHERE id = ?', (docente_id,))
            
            return {
                'nombre': docente_nombre,
                'usuario': docente_usuario,
                'horarios': len(horarios)
            }
    
    try:
        resultado = execute_with_retry(_eliminar)
        
        if resultado is None:
            return jsonify({'error': 'Docente no encontrado'}), 404
        
        log_action('admin', 'DOCENTE_ELIMINADO', 
                   f'Docente eliminado del sistema',
                   extra_data={
                       'docente_id': docente_id,
                       'docente_nombre': resultado['nombre'],
                       'docente_usuario': resultado['usuario'],
                       'horarios_eliminados': resultado['horarios']
                   })
        
        return jsonify({
            'success': True,
            'message': f'Docente {resultado["nombre"]} eliminado correctamente junto con {resultado["horarios"]} horario(s)'
        })
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_ELIMINAR_DOCENTE', e)
        return jsonify({'error': f'Error al eliminar docente: {str(e)}'}), 500

@app.route('/coordinador/cambiar_password_docente/<int:docente_id>', methods=['POST'])
@role_required(['coordinador'])
def cambiar_password_docente(docente_id):
    data = request.get_json()
    password_nueva = data.get('password_nueva')
    
    if not password_nueva:
        return jsonify({'error': 'La contraseña es obligatoria'}), 400
    
    if len(password_nueva) < 6:
        return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
    
    def _cambiar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT * FROM usuarios WHERE id = ? AND rol = "docente"', (docente_id,))
            docente = c.fetchone()
            
            if not docente:
                return None
            
            password_hash = hash_password(password_nueva)
            c.execute('UPDATE usuarios SET password = ? WHERE id = ?', (password_hash, docente_id))
            
            return docente
    
    try:
        docente = execute_with_retry(_cambiar)
        
        if docente is None:
            return jsonify({'error': 'Docente no encontrado'}), 404
        
        log_action('admin', 'PASSWORD_DOCENTE_CAMBIADA', 
                   f'Coordinador cambió contraseña de docente',
                   extra_data={'docente_id': docente_id, 'docente_nombre': docente['nombre']})
        
        return jsonify({
            'success': True,
            'message': f'Contraseña actualizada para {docente["nombre"]}'
        })
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_CAMBIAR_PASSWORD_DOCENTE', e)
        return jsonify({'error': 'Error al cambiar contraseña'}), 500

@app.route('/coordinador/actualizar_perfil', methods=['POST'])
@role_required(['coordinador'])
def coordinador_actualizar_perfil():
    data = request.get_json()
    nuevo_usuario = data.get('usuario', '').strip()
    nuevo_nombre = data.get('nombre', '').strip()
    nuevo_cargo = data.get('cargo', '').strip()
    password_actual = data.get('password_actual', '')
    
    if not nuevo_usuario or not nuevo_nombre or not nuevo_cargo:
        return jsonify({'error': 'Todos los campos son obligatorios'}), 400
    
    if len(nuevo_usuario) < 3:
        return jsonify({'error': 'El usuario debe tener al menos 3 caracteres'}), 400
    
    if len(nuevo_nombre) < 3:
        return jsonify({'error': 'El nombre debe tener al menos 3 caracteres'}), 400
    
    def _actualizar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            c.execute('SELECT usuario, password, nombre, cargo FROM usuarios WHERE id = ?', (session['usuario_id'],))
            usuario_actual = c.fetchone()
            
            if not usuario_actual or not verificar_password(password_actual, usuario_actual['password']):
                return None
            
            usuario_antiguo = usuario_actual['usuario']
            nombre_antiguo = usuario_actual['nombre']
            cargo_antiguo = usuario_actual['cargo']
            
            if nuevo_usuario != usuario_antiguo:
                c.execute('SELECT id FROM usuarios WHERE usuario = ? AND id != ?', (nuevo_usuario, session['usuario_id']))
                if c.fetchone():
                    return {'error': f'El usuario "{nuevo_usuario}" ya está en uso'}
            
            c.execute('''
                UPDATE usuarios 
                SET usuario = ?, nombre = ?, cargo = ?
                WHERE id = ?
            ''', (nuevo_usuario, nuevo_nombre, nuevo_cargo, session['usuario_id']))
            
            cambios = []
            if usuario_antiguo != nuevo_usuario:
                cambios.append(f'Usuario: {usuario_antiguo} → {nuevo_usuario}')
            if nombre_antiguo != nuevo_nombre:
                cambios.append(f'Nombre: {nombre_antiguo} → {nuevo_nombre}')
            if cargo_antiguo != nuevo_cargo:
                cambios.append(f'Cargo: {cargo_antiguo} → {nuevo_cargo}')
            
            return {'cambios': cambios}
    
    try:
        resultado = execute_with_retry(_actualizar)
        
        if resultado is None:
            log_action('admin', 'ACTUALIZAR_PERFIL_ERROR', 
                       'Intento de actualizar perfil con contraseña incorrecta',
                       level='warning')
            return jsonify({'error': 'Contraseña actual incorrecta'}), 400
        
        if 'error' in resultado:
            return jsonify(resultado), 400
        
        session['usuario'] = nuevo_usuario
        session['nombre'] = nuevo_nombre
        session['cargo'] = nuevo_cargo
        
        log_action('admin', 'PERFIL_COORDINADOR_ACTUALIZADO', 
                   'Perfil de coordinador actualizado exitosamente',
                   extra_data={'cambios': ', '.join(resultado['cambios'])})
        
        return jsonify({
            'success': True,
            'message': 'Perfil actualizado correctamente',
            'nuevo_usuario': nuevo_usuario,
            'nuevo_nombre': nuevo_nombre,
            'nuevo_cargo': nuevo_cargo
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': f'El usuario "{nuevo_usuario}" ya existe'}), 400
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_ACTUALIZAR_PERFIL', e)
        return jsonify({'error': f'Error al actualizar perfil: {str(e)}'}), 500

# ============================================================================
# RUTAS - RECTORADO
# ============================================================================

@app.route('/rectorado')
@role_required(['rectorado'])
def rectorado_dashboard():
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT h.*, u.nombre as docente_nombre, u.cargo as docente_cargo
                FROM horarios h
                JOIN usuarios u ON h.usuario_id = u.id
                WHERE h.estado = 'revision_rectorado'
                ORDER BY h.fecha_revision_coordinador ASC
            ''', ())
            return c.fetchall()
    
    try:
        horarios_pendientes = execute_with_retry(_obtener)
        
        log_action('admin', 'ACCESO_RECTORADO', 
                   f'Acceso al dashboard de rectorado',
                   extra_data={'horarios_pendientes': len(horarios_pendientes)})
        
        return render_template('rectorado_dashboard.html',
                             horarios=horarios_pendientes,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_DASHBOARD_RECTORADO', e)
        flash('Error al cargar dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/rectorado/revisar/<int:horario_id>')
@role_required(['rectorado'])
def rectorado_revisar(horario_id):
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT h.*, u.nombre as docente_nombre, u.cargo as docente_cargo
                FROM horarios h
                JOIN usuarios u ON h.usuario_id = u.id
                WHERE h.id = ?
            ''', (horario_id,))
            horario_row = c.fetchone()
            
            if not horario_row:
                return None, None
            
            horario_data = json.loads(horario_row['contenido_json'])
            
            c.execute('''
                SELECT o.*, u.nombre as revisor_nombre
                FROM observaciones o
                JOIN usuarios u ON o.revisor_id = u.id
                WHERE o.horario_id = ? AND o.tipo_revisor = 'rectorado' AND o.activa = 1
                ORDER BY o.fecha_observacion DESC
            ''', (horario_id,))
            observaciones = c.fetchall()
            
            observaciones_list = []
            for obs in observaciones:
                c.execute('SELECT * FROM observaciones_especificas WHERE observacion_id = ?', (obs['id'],))
                especificas = c.fetchall()
                
                observaciones_list.append({
                    'id': obs['id'],
                    'revisor_nombre': obs['revisor_nombre'],
                    'observacion_general': obs['observacion_general'],
                    'fecha': obs['fecha_observacion'],
                    'especificas': [dict(e) for e in especificas]
                })
            
            return horario_row, (horario_data, observaciones_list)
    
    try:
        horario_row, data = execute_with_retry(_obtener)
        
        if not horario_row:
            flash('Horario no encontrado', 'error')
            return redirect(url_for('rectorado_dashboard'))
        
        horario_data, observaciones_list = data
        horario_procesado = procesar_horario_para_visualizacion(horario_data)
        
        log_action('admin', 'REVISAR_HORARIO', 
                   f'Rectorado revisando horario',
                   extra_data={'horario_id': horario_id, 'docente': horario_row['docente_nombre']})
        
        return render_template('rectorado_revisar.html',
                             horario=horario_procesado,
                             horario_id=horario_id,
                             horario_info=horario_row,
                             observaciones=observaciones_list,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_REVISAR_RECTORADO', e)
        flash('Error al cargar horario', 'error')
        return redirect(url_for('rectorado_dashboard'))

@app.route('/rectorado/guardar_observaciones/<int:horario_id>', methods=['POST'])
@role_required(['rectorado'])
def rectorado_guardar_observaciones(horario_id):
    data = request.get_json()
    
    def _guardar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('''
                INSERT INTO observaciones (horario_id, revisor_id, tipo_revisor, observacion_general)
                VALUES (?, ?, 'rectorado', ?)
            ''', (horario_id, session['usuario_id'], data.get('observacion_general', '')))
            
            observacion_id = c.lastrowid
            
            for obs_esp in data.get('observaciones_especificas', []):
                c.execute('''
                    INSERT INTO observaciones_especificas (observacion_id, dia_id, periodo_id, comentario)
                    VALUES (?, ?, ?, ?)
                ''', (observacion_id, obs_esp['dia_id'], obs_esp['periodo_id'], obs_esp['comentario']))
            
            return observacion_id
    
    try:
        observacion_id = execute_with_retry(_guardar)
        
        log_action('admin', 'OBSERVACIONES_GUARDADAS', 
                   f'Rectorado guardó observaciones',
                   extra_data={
                       'horario_id': horario_id,
                       'observacion_id': observacion_id,
                       'num_especificas': len(data.get('observaciones_especificas', []))
                   })
        
        return jsonify({'success': True, 'observacion_id': observacion_id})
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_GUARDAR_OBSERVACIONES', e)
        return jsonify({'error': 'Error al guardar observaciones'}), 500

@app.route('/rectorado/aprobar/<int:horario_id>', methods=['POST'])
@role_required(['rectorado'])
def rectorado_aprobar(horario_id):
    def _aprobar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('SELECT usuario_id FROM horarios WHERE id = ?', (horario_id,))
            horario = c.fetchone()
            
            if not horario:
                return None
            
            c.execute('''
                UPDATE observaciones 
                SET activa = 0 
                WHERE horario_id = ? AND tipo_revisor = 'rectorado'
            ''', (horario_id,))
            
            c.execute('''
                UPDATE horarios 
                SET estado = 'aprobado',
                    revisor_rectorado_id = ?,
                    fecha_revision_rectorado = CURRENT_TIMESTAMP,
                    fecha_aprobacion = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (session['usuario_id'], horario_id))
            
            return True
    
    try:
        resultado = execute_with_retry(_aprobar)
        
        if resultado is None:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        log_action('admin', 'HORARIO_APROBADO_FINAL', 
                   f'Rectorado aprobó horario definitivamente',
                   extra_data={'horario_id': horario_id})
        
        return jsonify({'success': True, 'message': 'Horario aprobado definitivamente'})
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_APROBAR_RECTORADO', e)
        return jsonify({'error': 'Error al aprobar horario'}), 500

@app.route('/rectorado/rechazar/<int:horario_id>', methods=['POST'])
@role_required(['rectorado'])
def rectorado_rechazar(horario_id):
    def _rechazar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            
            c.execute('''
                UPDATE horarios 
                SET estado = 'rechazado_rectorado',
                    revisor_rectorado_id = ?,
                    fecha_revision_rectorado = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (session['usuario_id'], horario_id))
            
            return c.rowcount > 0
    
    try:
        resultado = execute_with_retry(_rechazar)
        
        if not resultado:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        log_action('admin', 'HORARIO_RECHAZADO_RECTORADO', 
                   f'Rectorado rechazó horario',
                   extra_data={'horario_id': horario_id})
        
        return jsonify({'success': True, 'message': 'Horario rechazado y devuelto al docente'})
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_RECHAZAR_RECTORADO', e)
        return jsonify({'error': 'Error al rechazar horario'}), 500

@app.route('/rectorado/configuracion', methods=['GET'])
@role_required(['rectorado'])
def rectorado_configuracion():
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT usuario, nombre, cargo FROM usuarios WHERE id = ?', (session['usuario_id'],))
            return c.fetchone()
    
    try:
        datos = execute_with_retry(_obtener)
        
        log_action('admin', 'ACCESO_CONFIGURACION_RECTORADO', 
                   'Acceso a configuración de rectorado')
        
        return render_template('rectorado_configuracion.html',
                             datos_actuales=datos,
                             nombre=session.get('nombre'),
                             cargo=session.get('cargo'),
                             rol=session.get('rol'))
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_CONFIG_RECTORADO', e)
        flash('Error al cargar configuración', 'error')
        return redirect(url_for('rectorado_dashboard'))

@app.route('/rectorado/actualizar_perfil', methods=['POST'])
@role_required(['rectorado'])
def rectorado_actualizar_perfil():
    data = request.get_json()
    nuevo_usuario = data.get('usuario', '').strip()
    nuevo_nombre = data.get('nombre', '').strip()
    nuevo_cargo = data.get('cargo', '').strip()
    password_actual = data.get('password_actual', '')
    
    if not nuevo_usuario or not nuevo_nombre or not nuevo_cargo:
        return jsonify({'error': 'Todos los campos son obligatorios'}), 400
    
    if len(nuevo_usuario) < 3:
        return jsonify({'error': 'El usuario debe tener al menos 3 caracteres'}), 400
    
    if len(nuevo_nombre) < 3:
        return jsonify({'error': 'El nombre debe tener al menos 3 caracteres'}), 400
    
    def _actualizar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            c.execute('SELECT usuario, password, nombre, cargo FROM usuarios WHERE id = ?', (session['usuario_id'],))
            usuario_actual = c.fetchone()
            
            if not usuario_actual or not verificar_password(password_actual, usuario_actual['password']):
                return None
            
            usuario_antiguo = usuario_actual['usuario']
            nombre_antiguo = usuario_actual['nombre']
            cargo_antiguo = usuario_actual['cargo']
            
            if nuevo_usuario != usuario_antiguo:
                c.execute('SELECT id FROM usuarios WHERE usuario = ? AND id != ?', (nuevo_usuario, session['usuario_id']))
                if c.fetchone():
                    return {'error': f'El usuario "{nuevo_usuario}" ya está en uso'}
            
            c.execute('''
                UPDATE usuarios 
                SET usuario = ?, nombre = ?, cargo = ?
                WHERE id = ?
            ''', (nuevo_usuario, nuevo_nombre, nuevo_cargo, session['usuario_id']))
            
            cambios = []
            if usuario_antiguo != nuevo_usuario:
                cambios.append(f'Usuario: {usuario_antiguo} → {nuevo_usuario}')
            if nombre_antiguo != nuevo_nombre:
                cambios.append(f'Nombre: {nombre_antiguo} → {nuevo_nombre}')
            if cargo_antiguo != nuevo_cargo:
                cambios.append(f'Cargo: {cargo_antiguo} → {nuevo_cargo}')
            
            return {'cambios': cambios}
    
    try:
        resultado = execute_with_retry(_actualizar)
        
        if resultado is None:
            log_action('admin', 'ACTUALIZAR_PERFIL_ERROR', 
                       'Intento de actualizar perfil con contraseña incorrecta',
                       level='warning')
            return jsonify({'error': 'Contraseña actual incorrecta'}), 400
        
        if 'error' in resultado:
            return jsonify(resultado), 400
        
        session['usuario'] = nuevo_usuario
        session['nombre'] = nuevo_nombre
        session['cargo'] = nuevo_cargo
        
        log_action('admin', 'PERFIL_RECTORADO_ACTUALIZADO', 
                   'Perfil de rectorado actualizado exitosamente',
                   extra_data={'cambios': ', '.join(resultado['cambios'])})
        
        return jsonify({
            'success': True,
            'message': 'Perfil actualizado correctamente',
            'nuevo_usuario': nuevo_usuario,
            'nuevo_nombre': nuevo_nombre,
            'nuevo_cargo': nuevo_cargo
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': f'El usuario "{nuevo_usuario}" ya existe'}), 400
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_ACTUALIZAR_PERFIL', e)
        return jsonify({'error': f'Error al actualizar perfil: {str(e)}'}), 500

@app.route('/rectorado/cambiar_password_propio', methods=['POST'])
@role_required(['rectorado'])
def rectorado_cambiar_password_propio():
    data = request.get_json()
    password_actual = data.get('password_actual', '')
    password_nueva = data.get('password_nueva', '')
    password_confirmar = data.get('password_confirmar', '')
    
    if not password_actual or not password_nueva or not password_confirmar:
        return jsonify({'error': 'Todos los campos son obligatorios'}), 400
    
    if password_nueva != password_confirmar:
        return jsonify({'error': 'Las contraseñas nuevas no coinciden'}), 400
    
    if len(password_nueva) < 6:
        return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
    
    if password_actual == password_nueva:
        return jsonify({'error': 'La nueva contraseña debe ser diferente a la actual'}), 400
    
    def _cambiar():
        with get_db_connection(write_mode=True) as conn:
            c = conn.cursor()
            c.execute('SELECT password FROM usuarios WHERE id = ?', (session['usuario_id'],))
            usuario = c.fetchone()
            
            if not usuario or not verificar_password(password_actual, usuario['password']):
                return None
            
            password_hash = hash_password(password_nueva)
            c.execute('UPDATE usuarios SET password = ? WHERE id = ?', 
                      (password_hash, session['usuario_id']))
            return True
    
    try:
        resultado = execute_with_retry(_cambiar)
        
        if resultado is None:
            log_action('admin', 'CAMBIO_PASSWORD_RECTORADO_ERROR', 
                       'Intento de cambio de contraseña con password actual incorrecta',
                       level='warning')
            return jsonify({'error': 'Contraseña actual incorrecta'}), 400
        
        log_action('admin', 'PASSWORD_RECTORADO_CAMBIADA', 
                   'Rectorado cambió su propia contraseña exitosamente')
        
        return jsonify({
            'success': True,
            'message': 'Contraseña actualizada correctamente'
        })
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_CAMBIAR_PASSWORD', e)
        return jsonify({'error': f'Error al cambiar contraseña: {str(e)}'}), 500

# ============================================================================
# RUTAS - DESCARGA Y VISUALIZACIÓN
# ============================================================================

@app.route('/api/horario/<int:horario_id>/data')
@login_required
def obtener_datos_horario(horario_id):
    def _obtener():
        with get_db_connection() as conn:
            c = conn.cursor()
            
            c.execute('SELECT * FROM horarios WHERE id = ?', (horario_id,))
            horario = c.fetchone()
            
            if not horario:
                return None
            
            if horario['estado'] != 'aprobado':
                return {'error': 'Solo se pueden descargar horarios aprobados'}
            
            if session.get('rol') == 'docente' and horario['usuario_id'] != session['usuario_id']:
                return {'error': 'No tienes permiso para descargar este horario'}
            
            c.execute('SELECT nombre, cargo FROM usuarios WHERE id = ?', (horario['usuario_id'],))
            docente = c.fetchone()
            
            coordinador_nombre = 'Coordinador de Carrera'
            coordinador_cargo = 'Coordinador'
            if horario['revisor_coordinador_id']:
                c.execute('SELECT nombre, cargo FROM usuarios WHERE id = ?', (horario['revisor_coordinador_id'],))
                coordinador = c.fetchone()
                if coordinador:
                    coordinador_nombre = coordinador['nombre']
                    coordinador_cargo = coordinador['cargo']
            
            rectorado_nombre = 'Rectorado'
            rectorado_cargo = 'Rector/a'
            if horario['revisor_rectorado_id']:
                c.execute('SELECT nombre, cargo FROM usuarios WHERE id = ?', (horario['revisor_rectorado_id'],))
                rectorado = c.fetchone()
                if rectorado:
                    rectorado_nombre = rectorado['nombre']
                    rectorado_cargo = rectorado['cargo']
            
            horario_data = json.loads(horario['contenido_json'])
            horario_procesado = procesar_horario_para_visualizacion(horario_data)
            
            horario_procesado['docente_nombre'] = docente['nombre'] if docente else 'Sin nombre'
            horario_procesado['docente_cargo'] = docente['cargo'] if docente else 'Sin cargo'
            horario_procesado['coordinador_nombre'] = coordinador_nombre
            horario_procesado['coordinador_cargo'] = coordinador_cargo
            horario_procesado['rectorado_nombre'] = rectorado_nombre
            horario_procesado['rectorado_cargo'] = rectorado_cargo
            horario_procesado['fecha_aprobacion'] = horario['fecha_aprobacion']
            horario_procesado['ciclo_academico'] = obtener_ciclo_academico()
            
            return horario_procesado
    
    try:
        resultado = execute_with_retry(_obtener)
        
        if resultado is None:
            return jsonify({'error': 'Horario no encontrado'}), 404
        
        if 'error' in resultado:
            return jsonify(resultado), 403
        
        log_action('horarios', 'DATOS_HORARIO_OBTENIDOS', 
                   f'Datos de horario obtenidos para descarga',
                   extra_data={'horario_id': horario_id})
        
        return jsonify(resultado)
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_OBTENER_DATOS', e)
        return jsonify({'error': f'Error al procesar horario: {str(e)}'}), 500

@app.route('/descargar/<int:horario_id>')
@login_required
def descargar_horario(horario_id):
    def _verificar():
        with get_db_connection() as conn:
            c = conn.cursor()
            
            c.execute('SELECT * FROM horarios WHERE id = ?', (horario_id,))
            horario = c.fetchone()
            
            if not horario:
                return None
            
            if horario['estado'] != 'aprobado':
                return {'error': 'Solo se pueden descargar horarios aprobados', 'redir': 'bandeja_docente'}
            
            if session.get('rol') == 'docente' and horario['usuario_id'] != session['usuario_id']:
                return {'error': 'No tienes permiso para descargar este horario', 'redir': 'bandeja_docente'}
            
            return {'horario': horario}
    
    try:
        resultado = execute_with_retry(_verificar)
        
        if resultado is None:
            flash('Horario no encontrado', 'error')
            return redirect(url_for('dashboard'))
        
        if 'error' in resultado:
            flash(resultado['error'], 'warning')
            return redirect(url_for(resultado['redir']))
        
        horario = resultado['horario']
        nombre_archivo = horario['nombre_archivo'].replace('.hored', '')
        
        log_action('horarios', 'ACCESO_DESCARGA_PDF', 
                   f'Acceso a página de descarga PDF',
                   extra_data={'horario_id': horario_id})
        
        return render_template('descargar_pdf.html',
                             horario_id=horario_id,
                             nombre_archivo=nombre_archivo)
    except Exception as e:
        log_error_with_traceback('horarios', 'ERROR_DESCARGAR', e)
        flash('Error al acceder a descarga', 'error')
        return redirect(url_for('dashboard'))

# ============================================================================
# MANEJO DE ERRORES
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    log_action('general', 'ERROR_404', 
               f'Página no encontrada: {request.url}',
               level='warning')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    log_error_with_traceback('general', 'ERROR_500', error)
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    log_error_with_traceback('general', 'ERROR_NO_MANEJADO', e)
    return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/admin/limpiar_huerfanos', methods=['POST'])
@role_required(['coordinador', 'rectorado'])
def admin_limpiar_huerfanos():
    try:
        archivos_eliminados, espacio_liberado = limpiar_archivos_huerfanos()
        
        return jsonify({
            'success': True,
            'message': f'Limpieza completada: {archivos_eliminados} archivos eliminados',
            'archivos_eliminados': archivos_eliminados,
            'espacio_liberado_mb': round(espacio_liberado / (1024*1024), 2)
        })
    except Exception as e:
        log_error_with_traceback('admin', 'ERROR_LIMPIEZA_MANUAL', e)
        return jsonify({'error': f'Error durante la limpieza: {str(e)}'}), 500

# ============================================================================
# CONFIGURACIÓN PARA PRODUCCIÓN
# ============================================================================

def configure_for_production():
    app.debug = False
    
    if not app.debug:
        file_handler = RotatingFileHandler(
            os.path.join(app.config['LOG_FOLDER'], 'production.log'),
            maxBytes=10*1024*1024,
            backupCount=10
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Aplicación iniciada en modo producción')

# Auto-inicializar la base de datos cuando se importe la app (para Gunicorn/Waitress)
def auto_init_db():
    """Inicializa la base de datos automáticamente si no existe"""
    try:
        db_path = app.config['DATABASE']
        
        # Si la base de datos no existe, crearla
        if not os.path.exists(db_path):
            print("=" * 80)
            print("AUTO-INICIALIZANDO BASE DE DATOS")
            print("=" * 80)
            init_db()
            print("✓ Base de datos creada exitosamente")
            print("=" * 80)
        else:
            # Verificar que las tablas existan
            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [row[0] for row in c.fetchall()]
                    
                    required_tables = ['usuarios', 'horarios', 'observaciones', 
                                      'observaciones_especificas', 'asignacion_actividades',
                                      'configuracion', 'actividades_complementarias']
                    
                    missing_tables = [t for t in required_tables if t not in tables]
                    
                    if missing_tables:
                        print(f"Tablas faltantes detectadas: {missing_tables}")
                        print("Reinicializando base de datos...")
                        init_db()
            except Exception as e:
                print(f"Error verificando base de datos: {e}")
                print("Reinicializando base de datos...")
                init_db()
        
        # Inicializar usuarios de forma silenciosa
        try:
            from setup_usuarios import inicializar_usuarios_sistema, verificar_sistema_inicializado
            
            if not verificar_sistema_inicializado(db_path):
                inicializar_usuarios_sistema(db_path)
        except:
            pass
                
    except Exception as e:
        print(f"ERROR en auto-inicialización: {e}")
        import traceback
        traceback.print_exc()

# Ejecutar auto-inicialización cuando se importe el módulo
auto_init_db()

# ============================================================================
# INICIO DE LA APLICACIÓN
# ============================================================================

if __name__ == '__main__':
    log_action('general', 'APLICACION_INICIADA', 
               f'Sistema de Gestión de Horarios - ISTT iniciado en {platform.system()}')
    
    init_db()
    
    is_production = os.environ.get('FLASK_ENV') == 'production'
    
    if is_production:
        configure_for_production()
        print("=" * 60)
        print("MODO PRODUCCIÓN DETECTADO")
        print("=" * 60)
        print(f"Sistema operativo: {platform.system()}")
        
        if IS_LINUX:
            print("\nPara Linux, ejecutar con Gunicorn:")
            print("gunicorn -w 4 -b 0.0.0.0:5050 --timeout 120 --max-requests 1000 --max-requests-jitter 100 app:app")
        elif IS_WINDOWS:
            print("\nPara Windows, ejecutar con Waitress:")
            print("waitress-serve --host=0.0.0.0 --port=5050 --threads=4 --channel-timeout=120 app:app")
        
        print("\nO usar el servidor de desarrollo (NO recomendado para producción):")
        print("python app.py")
        print("=" * 60)
        
    else:
        print("=" * 60)
        print("MODO DESARROLLO")
        print("=" * 60)
        print("Para producción, configura: export FLASK_ENV=production")
        print("=" * 60)
    
    app.run(
        debug=not is_production,
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5050)),
        threaded=True
    )
