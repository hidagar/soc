"""Parada pedida por systemd (SIGTERM) en los trabajos protegidos.

Antes se lanzaba TimeoutError, que es un OSError: los `except Exception` / `except OSError`
de conectores y bucles la absorbían y el trabajo seguía hasta que systemd lo mataba sin
ejecutar su limpieza. JobInterrupted no deriva de Exception: atraviesa esos bloques, y
`finally` y `transaction.atomic` sí se ejecutan (se deshace la transacción en curso).
"""
import signal


class JobInterrupted(BaseException):
    pass


def stop_on_sigterm():
    def interrupted(signum, frame):
        raise JobInterrupted('Trabajo interrumpido por systemd.')
    signal.signal(signal.SIGTERM, interrupted)
