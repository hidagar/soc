"""Recifrado de los campos encrypted_* con la clave principal de su familia (bloque 8).

Cada valor se atribuye a una familia de claves intentando descifrarlo: los tokens
Fernet están autenticados y solo la clave correcta los abre, así que no hace falta
un mapa manual campo→clave. Lo que no se puede descifrar se informa y no se toca.
Los informes nunca contienen valores, solo tablas, campos y recuentos.
"""
import os
from collections import Counter

from cryptography.fernet import InvalidToken
from django.apps import apps
from django.db import models, transaction

from .keyring import multifernet

CONNECTOR_KEYS = {'unifi': 'SOC_PORTAL_UNIFI_KEY', 'opnsense': 'SOC_PORTAL_OPNSENSE_KEY',
                  'ssh': 'SOC_PORTAL_SSH_KEY', 'mail': 'SOC_PORTAL_MAIL_KEY'}


def families():
    from .security import vault
    result = {'vault': vault()}
    for name, variable in CONNECTOR_KEYS.items():
        try:
            result[name] = multifernet(os.environ.get(variable, ''))
        except ValueError:
            pass  # Sin clave configurada: sus valores aparecerán como no descifrables.
    return result


def encrypted_fields():
    for model in apps.get_models():
        if not model._meta.managed or model._meta.proxy:
            continue
        for field in model._meta.concrete_fields:
            if field.name.startswith('encrypted_') and isinstance(field, (models.CharField, models.TextField)):
                yield model, field


def identify(token, keys):
    for name, box in keys.items():
        try:
            return name, box.decrypt(token.encode('ascii'))
        except (InvalidToken, UnicodeError, ValueError):
            continue
    return None, None


def rotate(apply=False):
    """Devuelve {(tabla, campo, familia|'sin descifrar'|'cambiado durante el recifrado'): filas}."""
    keys = families()
    report = Counter()
    for model, field in encrypted_fields():
        manager = model._base_manager
        rows = manager.exclude(**{field.attname: ''}).exclude(**{field.attname + '__isnull': True})
        with transaction.atomic():
            for pk, token in rows.values_list('pk', field.attname).iterator(chunk_size=500):
                family, plaintext = identify(token, keys)
                if family is None:
                    report[(model._meta.db_table, field.attname, 'sin descifrar')] += 1
                    continue
                if apply:
                    box = keys[family]
                    new = box.rotate(token.encode('ascii'))
                    if box.decrypt(new) != plaintext:
                        raise RuntimeError('El valor recifrado no coincide: recifrado detenido y deshecho.')
                    # Solo si nadie lo cambió mientras tanto.
                    if not manager.filter(pk=pk, **{field.attname: token}).update(**{field.attname: new.decode('ascii')}):
                        report[(model._meta.db_table, field.attname, 'cambiado durante el recifrado')] += 1
                        continue
                report[(model._meta.db_table, field.attname, family)] += 1
    return dict(report)
