import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEBUG = os.environ.get("SOC_PORTAL_DEBUG") == "1"
SECRET_KEY = os.environ.get("SOC_PORTAL_SECRET_KEY", "unsafe-development-key" if DEBUG else "")
if not SECRET_KEY:
    raise RuntimeError("SOC_PORTAL_SECRET_KEY is required outside development mode")
ALLOWED_HOSTS = os.environ.get("SOC_PORTAL_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
CSRF_TRUSTED_ORIGINS = [
    origin for origin in os.environ.get("SOC_PORTAL_CSRF_ORIGINS", "").split(",") if origin
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "core.security.SocSecurityMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

AUTHENTICATION_BACKENDS = ["core.email_auth.EmailBackend"]

ROOT_URLCONF = "socportal.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.debug",
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
        "core.context_processors.connection_permissions",
    ]},
}]
WSGI_APPLICATION = "socportal.wsgi.application"

# SQLite sigue siendo la base por defecto. PostgreSQL es opcional (bloque 4) y
# requiere requirements-postgresql.txt; la contraseña nunca va en Git.
SOC_DB_ENGINE = os.environ.get("SOC_PORTAL_DB_ENGINE", "sqlite")
if SOC_DB_ENGINE == "sqlite":
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "data" / "portal.sqlite3",
                             "OPTIONS": {"timeout": 30}}}
    if os.environ.get("SOC_PORTAL_DB_TEST_NAME"):
        # Solo pruebas: base de archivo para los ensayos de concurrencia (docs/testing.md).
        DATABASES["default"]["TEST"] = {"NAME": os.environ["SOC_PORTAL_DB_TEST_NAME"]}
elif SOC_DB_ENGINE == "postgresql":
    DATABASES = {"default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("SOC_PORTAL_DB_NAME", "socportal"),
        "USER": os.environ.get("SOC_PORTAL_DB_USER", "socportal"),
        "PASSWORD": os.environ.get("SOC_PORTAL_DB_PASSWORD", ""),
        "HOST": os.environ.get("SOC_PORTAL_DB_HOST", ""),
        "PORT": os.environ.get("SOC_PORTAL_DB_PORT", ""),
        "OPTIONS": {"sslmode": os.environ.get("SOC_PORTAL_DB_SSLMODE", "prefer")},
    }}
else:
    raise RuntimeError("SOC_PORTAL_DB_ENGINE must be 'sqlite' or 'postgresql'")
SOC_MFA_REQUIRED = os.environ.get('SOC_PORTAL_MFA_REQUIRED', '1') == '1'
SOC_PUBLIC_ORIGIN = os.environ.get('SOC_PUBLIC_ORIGIN','https://soc.ibred.es')
SOC_WAZUH_PROXY_KEY = os.environ.get('SOC_WAZUH_PROXY_KEY', '')
SESSION_COOKIE_AGE = 7200
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LANGUAGE_CODE = "es"
TIME_ZONE = "Europe/Madrid"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
EMAIL_BACKEND = os.environ.get("SOC_REPORT_EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
EMAIL_TIMEOUT = 20
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = not DEBUG
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

# CSRF rejection diagnostics (no request body or credentials).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"csrf_console": {"class": "logging.StreamHandler"}},
    "loggers": {"django.security.csrf": {
        "handlers": ["csrf_console"], "level": "WARNING", "propagate": False,
    }},
}
