"""Horario laboral para los plazos de atención.

Con el horario activado, los plazos solo corren dentro de la jornada (días de la semana, hora de inicio
y de fin, en la hora local del portal) y nunca en los festivos indicados. Se aplica a:

- las solicitudes normales de clientes (las urgentes y las sospechas de incidente siguen en tiempo
  natural, salvo que se indique lo contrario);
- las incidencias de gravedad media y baja, si se marca. Las altas y críticas cuentan siempre las 24 horas.

Un plazo de «8 h» son ocho horas de jornada: enviado un viernes a las 17:00 con jornada de 8:00 a 18:00,
vence el lunes a las 15:00.
"""
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta

from django.utils import timezone

MAX_DAYS = 800  # límite de seguridad al recorrer el calendario


@dataclass(frozen=True)
class Calendar:
    days: frozenset = frozenset({0, 1, 2, 3, 4})  # lunes = 0
    start: time = time(8, 0)
    end: time = time(18, 0)
    holidays: frozenset = field(default_factory=frozenset)

    def window(self, day):
        """(inicio, fin) de la jornada de ese día, con zona horaria, o None si no se trabaja."""
        if day.weekday() not in self.days or day in self.holidays:
            return None
        zone = timezone.get_current_timezone()
        return (timezone.make_aware(datetime.combine(day, self.start), zone), timezone.make_aware(datetime.combine(day, self.end), zone))

    def add(self, start, minutes):
        """Momento en que se cumplen `minutes` de jornada contados desde `start`."""
        remaining = timedelta(minutes=minutes)
        day = timezone.localtime(start).date()
        cursor = start
        for _ in range(MAX_DAYS):
            window = self.window(day)
            if window:
                begin = max(cursor, window[0])
                if begin < window[1]:
                    available = window[1] - begin
                    if remaining <= available:
                        return begin + remaining
                    remaining -= available
            day += timedelta(days=1)
        return cursor + remaining  # calendario sin días laborables suficientes: no se bloquea

    def between(self, start, end):
        """Minutos de jornada entre dos momentos (0 si `end` no es posterior)."""
        if end <= start:
            return 0
        total = timedelta(0)
        day = timezone.localtime(start).date()
        last = timezone.localtime(end).date()
        for _ in range(MAX_DAYS):
            if day > last:
                break
            window = self.window(day)
            if window:
                begin, finish = max(start, window[0]), min(end, window[1])
                if finish > begin:
                    total += finish - begin
            day += timedelta(days=1)
        return int(total.total_seconds() // 60)


def parse_days(values):
    days = frozenset(int(v) for v in values if str(v).isdigit() and 0 <= int(v) <= 6)
    if not days:
        raise ValueError('Marca al menos un día laborable.')
    return days


def parse_time(text, label):
    try:
        return datetime.strptime((text or '').strip()[:5], '%H:%M').time()
    except ValueError:
        raise ValueError(f'{label}: usa el formato HH:MM, por ejemplo 08:00.') from None


def parse_holidays(text):
    """Fechas dd/mm/aaaa, una por línea o separadas por comas."""
    result = []
    for raw in (text or '').replace(',', '\n').split('\n'):
        raw = raw.strip()
        if not raw:
            continue
        try:
            result.append(datetime.strptime(raw, '%d/%m/%Y').date())
        except ValueError:
            raise ValueError(f'Festivo «{raw[:20]}»: usa el formato dd/mm/aaaa.') from None
    if len(result) > 400:
        raise ValueError('Demasiados festivos.')
    return sorted(set(result))


def calendar_for(settings_row):
    """Calendario configurado, o None si el horario laboral está desactivado o es inválido."""
    if not settings_row or not settings_row.business_hours_enabled:
        return None
    try:
        days = parse_days(str(settings_row.business_days).split(','))
    except ValueError:
        return None
    if settings_row.business_start >= settings_row.business_end:
        return None
    holidays = frozenset(date.fromisoformat(d) for d in settings_row.business_holidays if isinstance(d, str))
    return Calendar(days=days, start=settings_row.business_start, end=settings_row.business_end, holidays=holidays)


def deadline(calendar, start, minutes):
    return calendar.add(start, minutes) if calendar else start + timedelta(minutes=minutes)


def remaining_minutes(calendar, now, limit):
    """Minutos que quedan hasta `limit` (de jornada si hay calendario)."""
    if limit <= now:
        return 0
    return calendar.between(now, limit) if calendar else int((limit - now).total_seconds() // 60)
