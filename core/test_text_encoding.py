"""Textos de la interfaz en UTF-8 limpio: sin acentos dañados por una doble conversión («atenciÃ³n»)."""
import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

# «Ã» o «Â» seguidos de un carácter de continuación: UTF-8 leído como Latin-1/Windows-1252 y guardado de nuevo.
DAMAGED = re.compile('[ÂÃ][\u0080-¿ŒœŠšŸŽž–—‘-„†-•…€™]')


class TextEncodingTests(SimpleTestCase):
    def test_templates_have_no_damaged_accents(self):
        damaged = []
        for path in sorted(Path(settings.BASE_DIR, 'templates').rglob('*')):
            if path.suffix in ('.html', '.txt'):
                text = path.read_text(encoding='utf-8')
                damaged += [f'{path.name}: {m.group(0)!r}' for m in DAMAGED.finditer(text)]
        self.assertEqual(damaged, [])
