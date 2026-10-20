#!/usr/bin/env python3
"""Generate static code references without importing Django or reading live data."""
import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'docs/reference'


def tree(path):
    return ast.parse(path.read_text(encoding='utf-8-sig'))


def link(path):
    return f'[{path.as_posix()}](../../{path.as_posix()})'


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def header(title):
    return [f'# {title}', '',
            'Generado desde el código por `python docs/tools/generate_reference.py`. '
            'No es telemetría ni una declaración de permisos efectivos.', '']


def modules():
    lines = header('Mapa de módulos')
    lines += ['La descripción procede del docstring cuando existe. '
              'Los nombres de símbolos ayudan a localizar código; leer el servicio '
              'y sus llamadas antes de atribuirle capacidades o ejecutar operaciones.', '',
              '| Módulo | Descripción / símbolos públicos de entrada |', '|---|---|']
    for path in sorted((ROOT / 'core').glob('*.py')):
        if path.stem.startswith('test') or path.stem == '__init__':
            continue
        parsed = tree(path)
        description = (ast.get_docstring(parsed) or '').split('\n')[0]
        symbols = [n.name for n in parsed.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
                   and not n.name.startswith('_')]
        entry = description + (' — ' if description and symbols else '')
        entry += ', '.join(f'`{name}`' for name in symbols[:14])
        if len(symbols) > 14:
            entry += ', … (ver archivo)'
        lines.append(f'| {link(path.relative_to(ROOT))} | {cell(entry)} |')
    lines += ['', '## Interfaz y activos', '',
              '| Directorio | Función |', '|---|---|',
              '| [templates](../../templates/) | HTML de servidor, formularios y correo. |',
              '| [static](../../static/) | CSS, JavaScript, logos y mapa. |',
              '| [public](../../public/) | Índice público de informes. |',
              '| [deploy](../../deploy/) | Instaladores, unidades, relay, reglas y utilidades. |']
    return lines


def models():
    lines = header('Modelos y campos')
    lines += ['Inventario estático de clases Django y campos declarados; no incluye '
              'campos ID automáticos ni tablas estándar de auth/sessions. Consultar constraints, clean/save, '
              'manager y migraciones para semántica y borrado. `blank` no significa '
              '`null`; un campo cifrado no debe mostrarse como dato de diagnóstico.', '']
    for path in sorted((ROOT / 'core').glob('*.py')):
        for node in tree(path).body:
            if not isinstance(node, ast.ClassDef) or not any(
                    isinstance(base, ast.Attribute) and base.attr == 'Model' for base in node.bases):
                continue
            lines += [f'## {node.name}', '', f'Fuente: {link(path.relative_to(ROOT))}.', '']
            lookup = next((ast.unparse(n.value) for n in node.body if isinstance(n, ast.Assign)
                           and any(isinstance(t, ast.Name) and t.id == 'customer_lookup' for t in n.targets)), None)
            if lookup:
                lines += [f'Ámbito declarado: `{lookup}`. Ver manager/middleware para aplicación.', '']
            lines += ['| Campo | Tipo | Relación / atributos declarados |', '|---|---|---|']
            for field in node.body:
                if not isinstance(field, ast.Assign) or not isinstance(field.value, ast.Call):
                    continue
                call = field.value
                if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name) or call.func.value.id != 'models':
                    continue
                if call.func.attr in ('Manager', 'UniqueConstraint', 'Index'):
                    continue
                name = ast.unparse(field.targets[0])
                details = []
                if call.func.attr in ('ForeignKey', 'OneToOneField', 'ManyToManyField') and call.args:
                    details.append('→ ' + ast.unparse(call.args[0]))
                for keyword in call.keywords:
                    if keyword.arg in ('null', 'blank', 'unique', 'db_index', 'primary_key', 'max_length', 'on_delete'):
                        details.append(keyword.arg + '=' + ast.unparse(keyword.value))
                lines.append(f'| `{name}` | {call.func.attr} | {cell("; ".join(details))} |')
    return lines


def routes():
    lines = header('Rutas y handlers')
    lines += ['Rutas extraídas de los URLconf, no una API REST pública estable. '
              'Métodos, autenticación, MFA, ámbito, permisos y respuestas se definen '
              'en middleware/decoradores/handler. Los parámetros de URL son identificadores, '
              'no credenciales; los tokens públicos sí deben custodiarse.', '']
    for relative in ('socportal/urls.py', 'core/urls.py'):
        lines += [f'## {relative}', '', '| Ruta | Nombre | Handler |', '|---|---|---|']
        for node in ast.walk(tree(ROOT / relative)):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'path' or len(node.args) < 2:
                continue
            route = ast.literal_eval(node.args[0])
            name = next((ast.literal_eval(k.value) for k in node.keywords if k.arg == 'name'), '')
            lines.append(f'| `{cell(route or "/")}` | `{cell(name)}` | `{cell(ast.unparse(node.args[1]))}` |')
    return lines


def environment():
    entries = {}
    files = sorted((ROOT / 'core').glob('*.py')) + sorted((ROOT / 'socportal').glob('*.py'))
    for path in files:
        for node in ast.walk(tree(path)):
            if (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and ast.unparse(node.func) in ('os.getenv', 'os.environ.get')):
                entries.setdefault(node.args[0].value, set()).add(path.relative_to(ROOT))
    lines = header('Variables de entorno: lectores reales')
    lines += ['Valores, formatos y secretos: [configuración](../configuration.md). '
              'Se enumeran lecturas literales, no toda configuración en archivos, '
              'base de datos, systemd o rutas fijas. No se imprimen valores del entorno.', '',
              '| Variable | Lectores |', '|---|---|']
    for name, readers in sorted(entries.items()):
        lines.append(f'| `{name}` | ' + ', '.join(link(p) for p in sorted(readers)) + ' |')
    return lines


def jobs():
    lines = header('Comandos, trabajos y unidades')
    lines += ['Estos comandos pueden escribir, configurar equipos, enviar correo o '
              'cambiar el sistema. Revisar [operación](../operations.md) y permisos root; '
              'el inventario no autoriza su ejecución.', '',
              '| Comando manage.py | Argumentos declarados |', '|---|---|']
    for path in sorted((ROOT / 'core/management/commands').glob('*.py')):
        if path.stem == '__init__':
            continue
        arguments = []
        for node in ast.walk(tree(path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument':
                arguments.append(ast.unparse(node))
        lines.append(f'| {link(path.relative_to(ROOT))} | {cell("; ".join(arguments) or "Sin argumentos propios")} |')
    lines += ['', '## Dispatcher', '', '| Trabajo | Intervalo objetivo (s) | Etiqueta |', '|---|---:|---|']
    for node in tree(ROOT / 'core/background_jobs.py').body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'JOBS' for t in node.targets):
            for name, (seconds, label) in ast.literal_eval(node.value).items():
                lines.append(f'| `{name}` | {seconds} | {label} |')
    lines += ['', '## Unidades incluidas', '',
              'La unidad instalada puede tener overrides no presentes en Git. '
              'Consultar su configuración real antes de programar otra tarea.', '']
    for path in sorted((ROOT / 'deploy').rglob('*')):
        if path.suffix in ('.service', '.timer'):
            lines.append('- ' + link(path.relative_to(ROOT)))
    return lines


def verification():
    lines = header('Migraciones y pruebas')
    lines += ['Los nombres ayudan a navegar; un método presente no significa '
              'que se haya ejecutado ni que cubra todos los casos. Los decorators '
              'pueden omitir ensayos que exigen Linux/archivo/motor real.', '',
              '## Módulos de pruebas', '', '| Módulo | Métodos `test_*` declarados |', '|---|---:|']
    for path in sorted((ROOT / 'core').glob('test*.py')):
        count = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_') for n in ast.walk(tree(path)))
        lines.append(f'| {link(path.relative_to(ROOT))} | {count} |')
    lines += ['', '## Migraciones', '', 'No editar migraciones aplicadas; ver dependencias/operaciones reales.', '']
    for path in sorted((ROOT / 'core/migrations').glob('[0-9]*.py')):
        lines.append('- ' + link(path.relative_to(ROOT)))
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Report stale references without writing')
    options = parser.parse_args()
    outputs = {'modules.md': modules(), 'models.md': models(), 'routes.md': routes(),
               'environment.md': environment(), 'jobs.md': jobs(), 'verification.md': verification()}
    changed = []
    for name, lines in outputs.items():
        path = TARGET / name
        content = '\n'.join(lines).rstrip() + '\n'
        if not path.exists() or path.read_text(encoding='utf-8') != content:
            changed.append(name)
            if not options.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding='utf-8')
    if options.check and changed:
        print('Referencias desactualizadas: ' + ', '.join(changed))
        return 1
    print(('Referencias verificadas' if options.check else 'Referencias generadas') + f': {len(outputs)} archivos')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
