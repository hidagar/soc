#!/usr/bin/env python3
"""Lee /etc/soc-portal/portal.env con las reglas de EnvironmentFile de systemd.

Los scripts de despliegue no deben cargar el archivo con `source`: con `set -u` un `$`
en una contraseña aborta el script y un espacio sin comillas ejecuta un comando, mientras
que systemd (y por tanto el portal) los acepta como texto. Aquí no hay expansión de `$`
ni de comandos: comillas simples literales, dobles con escapes `\\`, comentarios con `#`
o `;` al inicio de línea y claves con nombre de variable válido (las demás se ignoran).

    envfile.py --get NOMBRE ARCHIVO     valor (la última asignación gana)
    envfile.py --shell ARCHIVO          líneas `export NOMBRE='valor'` seguras para eval
    envfile.py --fingerprints ARCHIVO   huella SHA-256 de cada clave de cifrado, nunca la clave
"""
import hashlib
import re
import shlex
import sys

NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
# Variables cuyas claves cifran datos de la base (lista «nueva,anterior» salvo SECRET_KEY).
KEY_VARIABLES = ('SOC_PORTAL_SECRET_KEY', 'SOC_PORTAL_VAULT_KEYS', 'SOC_PORTAL_UNIFI_KEY',
                 'SOC_PORTAL_OPNSENSE_KEY', 'SOC_PORTAL_SSH_KEY', 'SOC_PORTAL_MAIL_KEY')


def _value(text, start):
    """Valor desde `start` hasta el fin de la asignación; devuelve (valor, posición siguiente)."""
    out, i, quote = [], start, None
    while i < len(text):
        char = text[i]
        if quote == "'":
            if char == "'":
                quote = None
            else:
                out.append(char)
        elif quote == '"':
            if char == '"':
                quote = None
            elif char == '\\' and i + 1 < len(text):
                i += 1
                if text[i] != '\n':  # barra al final de línea: continuación
                    out.append(text[i] if text[i] in '"\\`$' else '\\' + text[i])
            else:
                out.append(char)
        elif char in '\'"':
            quote = char
        elif char == '\\' and i + 1 < len(text):
            i += 1
            if text[i] != '\n':
                out.append(text[i])
        elif char == '\n':
            break
        else:
            out.append(char)
        i += 1
    value = ''.join(out)
    return value.rstrip() if quote is None else value, i + 1


def parse(text):
    values, i = {}, 0
    while i < len(text):
        end = text.find('\n', i)
        end = len(text) if end < 0 else end
        line = text[i:end].lstrip()
        if not line or line[0] in '#;' or '=' not in line:
            i = end + 1
            continue
        key = line.split('=', 1)[0].strip()
        offset = i + (end - i - len(line)) + line.index('=') + 1
        while offset < len(text) and text[offset] in ' \t':
            offset += 1
        value, i = _value(text, offset)
        if NAME.match(key):
            values[key] = value
    return values


def fingerprints(values):
    for name in KEY_VARIABLES:
        raw = values.get(name, '')
        keys = [raw] if name == 'SOC_PORTAL_SECRET_KEY' else raw.split(',')
        for key in (k.strip() for k in keys):
            if key:
                yield name, hashlib.sha256(key.encode()).hexdigest()


def main(argv):
    if len(argv) == 3 and argv[0] == '--get':
        values = parse(open(argv[2], encoding='utf-8').read())
        print(values.get(argv[1], ''))
    elif len(argv) == 2 and argv[0] == '--shell':
        for key, value in parse(open(argv[1], encoding='utf-8').read()).items():
            print(f'export {key}={shlex.quote(value)}')
    elif len(argv) == 2 and argv[0] == '--fingerprints':
        for name, digest in fingerprints(parse(open(argv[1], encoding='utf-8').read())):
            print(name, digest)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
