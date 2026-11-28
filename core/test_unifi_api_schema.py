"""Lo que el SOC escribe en UniFi cumple el esquema oficial de la API de Network 10.1.84 y 11.0.97.

Los esquemas son un subconjunto de la especificación pública (core/fixtures/unifi_network_api). Al salir una
versión nueva: añadir su subconjunto y su número a VERSIONS; si una petición deja de cumplirlo, esta prueba falla.
"""
import json
import re
from pathlib import Path
from unittest import mock

from . import qfeeds_distribution, unifi_blocklist
from .models import BlocklistFeed, UnifiBlocklistBinding
from .test_unifi_blocklist import SOC_LIST, UnifiTestCase

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'unifi_network_api'
VERSIONS = ('10.1.84', '11.0.97')
UUID = re.compile(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
TYPES = {'object': dict, 'array': list, 'string': str, 'boolean': bool, 'integer': int}


def schemas(version):
    return json.loads((FIXTURES / f'{version}.json').read_text())['schemas']


def validate(value, schema, defs, path='$', skip_discriminator=False):
    """Validador mínimo de OpenAPI 3 para estos esquemas: $ref, allOf, discriminator, tipos, requeridos, enum, uuid."""
    errors = []
    if '$ref' in schema:
        return validate(value, defs[schema['$ref'].rsplit('/', 1)[1]], defs, path, skip_discriminator)
    disc = schema.get('discriminator')
    if disc and not skip_discriminator and isinstance(value, dict):
        target = disc['mapping'].get(value.get(disc['propertyName']))
        if not target:
            return [f'{path}: {disc["propertyName"]}={value.get(disc["propertyName"])!r} no admitido']
        return validate(value, defs[target.rsplit('/', 1)[1]], defs, path, False)
    for part in schema.get('allOf', []):
        # La parte base del discriminador ya se ha elegido: no volver a resolverlo.
        errors += validate(value, part, defs, path, skip_discriminator=True)
    expected = TYPES.get(schema.get('type'))
    if expected and (not isinstance(value, expected) or (expected is int and isinstance(value, bool))):
        return errors + [f'{path}: se esperaba {schema["type"]}']
    if 'enum' in schema and value not in schema['enum']:
        errors.append(f'{path}: {value!r} fuera de {schema["enum"]}')
    if schema.get('format') == 'uuid' and isinstance(value, str) and not UUID.match(value):
        errors.append(f'{path}: no es un uuid')
    if isinstance(value, dict):
        for name in schema.get('required', []):
            if name not in value:
                errors.append(f'{path}: falta {name}')
        for name, sub in (schema.get('properties') or {}).items():
            if name in value and value[name] is not None:
                errors += validate(value[name], sub, defs, f'{path}.{name}')
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0):
            errors.append(f'{path}: menos de {schema["minItems"]} elementos')
        if 'items' in schema:
            for index, item in enumerate(value):
                errors += validate(item, schema['items'], defs, f'{path}[{index}]')
    return errors


class SchemaSelfTest(UnifiTestCase):
    def test_the_validator_catches_what_unifi_would_reject(self):
        defs = schemas('11.0.97')
        policy = defs['Create or update firewall policy']
        self.assertIn('falta action', ' '.join(validate({'enabled': False, 'name': 'x'}, policy, defs)))
        bad = {'type': 'IPV4_ADDRESSES', 'name': 'SOC', 'items': [{'type': 'RANGO', 'value': '1.2.3.4'}]}
        self.assertTrue(validate(bad, defs['Create or update traffic matching list'], defs))


class UnifiRequestsMatchTheOfficialSchema(UnifiTestCase):
    def setUp(self):
        super().setUp()
        BlocklistFeed.objects.filter(pk=self.feed.pk).update(qfeeds_dns=True, qfeeds_preventive=True)
        self.sent = []
        original = self.console.__call__

        def record(api_key, host_id, path, method='GET', payload=None, query=None):
            if method in ('POST', 'PUT') and payload is not None and '/ordering' not in path:
                kind = 'list' if '/traffic-matching-lists' in path else 'policy'
                self.sent.append((kind, method, path, json.loads(json.dumps(payload))))
            return original(api_key, host_id, path, method, payload, query)
        patcher = mock.patch.object(unifi_blocklist, 'call', side_effect=record)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, value in (('servable_dns', ['malo.example.com', 'c2.example.net']), ('servable_preventive', ['45.155.205.10'])):
            patcher = mock.patch.object(qfeeds_distribution, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def exercise(self):
        url = self.login()
        for direction in ('in', 'out', 'qfeeds', 'qout', 'dns'):
            self.client.post(url, {'action': 'unifi_create', 'device': self.device.pk, 'direction': direction})
        for binding in UnifiBlocklistBinding.objects.all():
            self.client.post(url, {'action': 'unifi_policy_enable', 'binding': binding.pk})
            unifi_blocklist.sync(binding, force=True)

    def test_every_list_and_policy_written_is_valid_in_each_version(self):
        self.exercise()
        kinds = {(kind, method) for kind, method, _, _ in self.sent}
        self.assertEqual(kinds, {('list', 'POST'), ('list', 'PUT'), ('policy', 'POST'), ('policy', 'PUT')})
        self.assertEqual(UnifiBlocklistBinding.objects.count(), 5)
        for version in VERSIONS:
            defs = schemas(version)
            for kind, method, path, body in self.sent:
                root = 'Create or update traffic matching list' if kind == 'list' else 'Create or update firewall policy'
                with self.subTest(version=version, method=method, path=path):
                    self.assertEqual(validate(body, defs[root], defs), [])

    def test_policy_rewrites_drop_only_read_only_fields(self):
        """Al reescribir una política se quitan `id`, `index` y `metadata`: siguen siendo los únicos de solo lectura."""
        for version in VERSIONS:
            defs = schemas(version)
            read_only = set(defs['Firewall policy']['properties']) - set(defs['Create or update firewall policy']['properties'])
            self.assertEqual(read_only, {'id', 'index', 'metadata'}, version)

    def test_policies_reported_by_version_11_keep_their_flow_reporting(self):
        """En 11.0.97 la política trae `reportFlowEnabled`; al activarla se conserva lo que haya en UniFi."""
        self.exercise()
        policy_id = next(p['id'] for b in UnifiBlocklistBinding.objects.filter(direction='in') for p in b.policies)
        self.console.policies[policy_id]['reportFlowEnabled'] = False
        binding = UnifiBlocklistBinding.objects.get(direction='in')
        self.sent.clear()
        unifi_blocklist.set_policies(binding, True)
        [(_, _, _, body)] = [s for s in self.sent if policy_id in s[2]]
        self.assertIs(body['reportFlowEnabled'], False)
        defs = schemas('11.0.97')
        self.assertEqual(validate(body, defs['Create or update firewall policy'], defs), [])
        self.assertNotIn(SOC_LIST, json.dumps(body), 'la política usa su propia lista, no la del operador')
