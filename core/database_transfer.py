"""Traslado verificado de la base del portal de SQLite a PostgreSQL (bloque 4, paso 4).

El origen se abre en solo lectura y el destino es la conexión ``default``, que debe
ser PostgreSQL con las mismas migraciones aplicadas. Todo se copia en una única
transacción conservando claves primarias, relaciones y textos cifrados; antes de
confirmar se comparan filas y huellas por tabla, y cualquier diferencia deshace
el traslado. Los informes nunca incluyen valores: pueden contener secretos.
"""
import hashlib
import ipaddress
import json
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

from django.apps import apps
from django.core.management.color import no_style
from django.db import connections, models, transaction
from django.db.utils import ConnectionDoesNotExist

SOURCE = 'transfer_source'
CHUNK = 2000
INT_RANGES = {
    'SmallIntegerField': (-2**15, 2**15 - 1), 'PositiveSmallIntegerField': (0, 2**15 - 1),
    'IntegerField': (-2**31, 2**31 - 1), 'PositiveIntegerField': (0, 2**31 - 1),
}
BUSINESS_TABLES = ('core.Client', 'auth.User')


class TransferError(Exception):
    pass


def close_source():
    try:
        connections[SOURCE].close()
        del connections[SOURCE]
    except (ConnectionDoesNotExist, AttributeError):
        pass


def open_source(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise TransferError(f'No existe la base de origen: {path}')
    # Una conexión nueva por traslado. Se registra solo para crearla: el origen no queda
    # como base configurada que otro código pudiera usar por accidente.
    close_source()
    config = {'ENGINE': 'django.db.backends.sqlite3', 'NAME': f'file:{path}?mode=ro', 'OPTIONS': {'uri': True}}
    configured = connections.configure_settings({'default': connections.settings['default'], SOURCE: config})
    connections.settings[SOURCE] = configured[SOURCE]
    try:
        source = connections[SOURCE]
    finally:
        del connections.settings[SOURCE]
    source.ensure_connection()
    return SOURCE


def transfer_models():
    return [model for model in apps.get_models(include_auto_created=True)
            if model._meta.managed and not model._meta.proxy]


def applied_migrations(alias):
    with connections[alias].cursor() as cursor:
        cursor.execute('SELECT app, name FROM django_migrations')
        return set(cursor.fetchall())


def check_target():
    target = connections['default']
    if target.vendor != 'postgresql':
        raise TransferError('El destino (default) debe ser PostgreSQL: SOC_PORTAL_DB_ENGINE=postgresql.')
    occupied = [label for label in BUSINESS_TABLES if apps.get_model(label)._base_manager.using('default').exists()]
    if occupied:
        raise TransferError('El destino ya contiene datos (' + ', '.join(occupied) + '). Usa una base PostgreSQL nueva.')


def preflight(alias):
    """Datos que SQLite admite y PostgreSQL rechaza. Devuelve {(tabla, campo, problema): filas}."""
    issues = Counter()
    for model in transfer_models():
        fields = model._meta.concrete_fields
        names = [field.attname for field in fields]
        for row in model._base_manager.using(alias).values_list(*names).iterator(chunk_size=CHUNK):
            for field, value in zip(fields, row):
                problem = field_problem(field, value)
                if problem:
                    issues[(model._meta.db_table, field.attname, problem)] += 1
    with connections[alias].cursor() as cursor:
        cursor.execute('PRAGMA foreign_key_check')
        for table, *_ in cursor.fetchall():
            issues[(table, '-', 'clave foránea sin destino')] += 1
    return dict(issues)


def field_problem(field, value):
    if value is None:
        return None
    kind = field.get_internal_type()
    if isinstance(field, models.JSONField):
        return 'carácter NUL en JSON' if '\\u0000' in json.dumps(value) else None
    if isinstance(value, str) and '\x00' in value:
        return 'carácter NUL en texto'
    if isinstance(field, models.GenericIPAddressField):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return 'IP no válida'
        return None
    if kind in INT_RANGES:
        low, high = INT_RANGES[kind]
        return 'entero fuera de rango' if not low <= value <= high else None
    if getattr(field, 'max_length', None) and isinstance(value, str) and len(value) > field.max_length:
        return 'texto más largo que max_length'
    return None


@contextmanager
def preserved_timestamps(model_list):
    # bulk_create llama a pre_save: auto_now/auto_now_add reescribirían las fechas históricas.
    changed = []
    for model in model_list:
        for field in model._meta.concrete_fields:
            for flag in ('auto_now', 'auto_now_add'):
                if getattr(field, flag, False):
                    setattr(field, flag, False)
                    changed.append((field, flag))
    try:
        yield
    finally:
        for field, flag in changed:
            setattr(field, flag, True)


def normalized(field, value):
    if value is None:
        return None
    if isinstance(field, models.JSONField):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if isinstance(field, models.GenericIPAddressField):
        return str(ipaddress.ip_address(value))
    if isinstance(value, datetime):
        return value.astimezone(dt_timezone.utc).isoformat()
    if isinstance(value, memoryview):
        return bytes(value)  # Defensa: psycopg2 devolvía bytea como memoryview (psycopg 3, como bytes).
    return value


def fingerprint(model, alias):
    """Filas y huella independiente del orden (la intercalación de textos difiere entre motores)."""
    fields = model._meta.concrete_fields
    total, mixed, count = 0, 0, 0
    for row in model._base_manager.using(alias).values_list(*[f.attname for f in fields]).iterator(chunk_size=CHUNK):
        digest = int.from_bytes(hashlib.sha256(repr(tuple(
            normalized(field, value) for field, value in zip(fields, row))).encode()).digest(), 'big')
        total = (total + digest) % 2**256
        mixed ^= digest
        count += 1
    return count, f'{total:064x}{mixed:064x}'


def copy_rows(model, source):
    manager = model._base_manager
    batch = []
    for obj in manager.using(source).iterator(chunk_size=CHUNK):
        batch.append(obj)
        if len(batch) >= CHUNK:
            manager.using('default').bulk_create(batch)
            batch = []
    if batch:
        manager.using('default').bulk_create(batch)


def transfer(source_path, progress=None):
    """Copia y verifica. Devuelve [(tabla, filas)]; lanza TransferError y no deja datos si algo difiere."""
    source = open_source(source_path)
    check_target()
    missing = applied_migrations(source) ^ applied_migrations('default')
    if missing:
        raise TransferError('Origen y destino no tienen las mismas migraciones aplicadas '
                            f'({len(missing)} diferencias). Ejecuta migrate con el mismo commit en ambos.')
    issues = preflight(source)
    if issues:
        raise TransferError(f'El origen tiene {sum(issues.values())} valores que PostgreSQL rechazaría. '
                            'Revisa la comprobación previa (--check).')
    model_list = transfer_models()
    target = connections['default']
    report = []
    with transaction.atomic(using='default'), preserved_timestamps(model_list):
        tables = [model._meta.db_table for model in model_list]
        with target.cursor() as cursor:
            # Las semillas de las migraciones (grupos, permisos, tipos) se sustituyen por las del origen.
            for sql in target.ops.sql_flush(no_style(), tables, reset_sequences=True, allow_cascade=True):
                cursor.execute(sql)
        for model in model_list:
            copy_rows(model, source)
            if progress:
                progress(model._meta.db_table)
        with target.cursor() as cursor:
            for sql in target.ops.sequence_reset_sql(no_style(), model_list):
                cursor.execute(sql)
        for model in model_list:
            expected, got = fingerprint(model, source), fingerprint(model, 'default')
            if expected != got:
                raise TransferError(f'{model._meta.db_table}: filas o contenido distintos tras copiar '
                                    f'({expected[0]} en origen, {got[0]} en destino). Traslado deshecho.')
            report.append((model._meta.db_table, expected[0]))
    from django.contrib.contenttypes.models import ContentType
    ContentType.objects.clear_cache()
    return report
