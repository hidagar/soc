"""Canonical equipment MAC identifiers; transport IP is a separate identity."""
import re
from django import forms
from django.core.exceptions import ValidationError
from django.db import models


def normalize_mac(value):
    if value is None or value == '':
        return None
    value = str(value).strip()
    if not value:
        return None
    patterns = (r'[0-9a-fA-F]{12}', r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',
                r'(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}', r'(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}')
    if not any(re.fullmatch(pattern, value) for pattern in patterns):
        raise ValidationError('Introduce una MAC válida, por ejemplo 00:0B:82:12:34:56.', code='invalid')
    compact = re.sub('[:.\u002d]', '', value).upper()
    if compact == '000000000000' or int(compact[:2], 16) & 1:
        raise ValidationError('Usa la MAC propia del equipo; no una dirección nula, multicast o broadcast.', code='invalid')
    return ':'.join(compact[i:i + 2] for i in range(0, 12, 2))


class MacFormField(forms.CharField):
    def to_python(self, value):
        return normalize_mac(value)


class MacAddressField(models.CharField):
    def to_python(self, value):
        return normalize_mac(value)

    def formfield(self, **kwargs):
        # Allow noncanonical input; normalize before enforcing the stored length.
        kwargs.setdefault('max_length', 32)
        kwargs.setdefault('form_class', MacFormField)
        return super().formfield(**kwargs)
