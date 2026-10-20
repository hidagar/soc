"""Claves Fernet con rotación: una lista «nueva,anterior» cifra con la primera y descifra con cualquiera.

Las variables SOC_PORTAL_*_KEY admiten varias claves separadas por comas. Tras añadir
una clave nueva al principio, `manage.py rotate_encryption_keys --apply` vuelve a cifrar
los valores guardados con ella; después la anterior puede retirarse. Ver docs/security.md.
"""
from cryptography.fernet import Fernet, MultiFernet


def keys_from(value):
    return [key.strip() for key in (value or '').split(',') if key.strip()]


def multifernet(value, legacy=()):
    """MultiFernet de las claves de `value` (la primera cifra) más las heredadas al final.

    Lanza ValueError si no hay ninguna clave o alguna no es una clave Fernet válida.
    """
    fernets = [Fernet(key.encode('ascii')) for key in keys_from(value)] + list(legacy)
    if not fernets:
        raise ValueError('Sin claves de cifrado')
    return MultiFernet(fernets)
