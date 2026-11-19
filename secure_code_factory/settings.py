
"""
Django settings for secure_code_factory project.
Development and Render production configuration.
"""

import os
from pathlib import Path

import dj_database_url

from django.core.exceptions import ImproperlyConfigured


# ==========================================
# BASE DIRECTORY
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ==========================================
# SECURITY AND ENVIRONMENT SETTINGS
# ==========================================

# Enable DEBUG locally and disable it automatically on Render.
DEBUG = os.environ.get(
    "DEBUG",
    "False" if "RENDER" in os.environ else "True"
).strip().lower() in ("true", "1", "yes")

# Read the secret key from environment variables.
SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:

    if DEBUG:
        SECRET_KEY = (
            "django-insecure-local-development-only-key-"
            "never-use-in-production"
        )

    else:
        raise ImproperlyConfigured(
            "SECRET_KEY must be configured in production."
        )


# ==========================================
# ALLOWED HOSTS
# ==========================================

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
]

RENDER_EXTERNAL_HOSTNAME = os.environ.get(
    "RENDER_EXTERNAL_HOSTNAME"
)

if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# Support additional custom domains.
extra_hosts = os.environ.get("ALLOWED_HOSTS", "")

ALLOWED_HOSTS.extend(
    host.strip()
    for host in extra_hosts.split(",")
    if host.strip()
)


# ==========================================
# CSRF TRUSTED ORIGINS
# ==========================================

CSRF_TRUSTED_ORIGINS = []

if RENDER_EXTERNAL_HOSTNAME:
    CSRF_TRUSTED_ORIGINS.append(
        f"https://{RENDER_EXTERNAL_HOSTNAME}"
    )

extra_origins = os.environ.get(
    "CSRF_TRUSTED_ORIGINS", ""
)

CSRF_TRUSTED_ORIGINS.extend(
    origin.strip()
    for origin in extra_origins.split(",")
    if origin.strip()
)


# ==========================================
# INSTALLED APPLICATIONS
# ==========================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'security_monitor',
]


# ==========================================
# MIDDLEWARE
# ==========================================

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',

    # Serve static files in production.
    'whitenoise.middleware.WhiteNoiseMiddleware',

    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


ROOT_URLCONF = 'secure_code_factory.urls'


# ==========================================
# TEMPLATES
# ==========================================

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,

        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


WSGI_APPLICATION = 'secure_code_factory.wsgi.application'


# ==========================================
# DATABASE CONFIGURATION
# SQLITE LOCALLY
# POSTGRESQL ON RENDER
# ==========================================

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:

    DATABASES = {
        'default': dj_database_url.parse(
            DATABASE_URL,
            conn_max_age=600
        )
    }

elif DEBUG:

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

else:

    raise ImproperlyConfigured(
        "DATABASE_URL must be configured in production."
    )


# ==========================================
# PASSWORD VALIDATION
# ==========================================

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# ==========================================
# INTERNATIONALIZATION
# ==========================================

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# ==========================================
# STATIC FILES
# ==========================================

STATIC_URL = '/static/'

STATIC_ROOT = BASE_DIR / 'staticfiles'

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },

    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}


# ==========================================
# EMAIL CONFIGURATION
# Django 6.1 MAILERS setting
# ==========================================

MAILERS = {
    'default': {
        'BACKEND': 'django.core.mail.backends.console.EmailBackend',
    },
}


# ==========================================
# PRODUCTION SECURITY SETTINGS
# ==========================================

# Render terminates HTTPS at its proxy.
SECURE_PROXY_SSL_HEADER = (
    'HTTP_X_FORWARDED_PROTO',
    'https'
)

# Enable secure settings automatically outside development.
SECURE_SSL_REDIRECT = not DEBUG

SESSION_COOKIE_SECURE = not DEBUG

CSRF_COOKIE_SECURE = not DEBUG

SECURE_CONTENT_TYPE_NOSNIFF = True

X_FRAME_OPTIONS = 'DENY'

SECURE_REFERRER_POLICY = 'same-origin'

SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'


# ==========================================
# DEFAULT PRIMARY KEY
# ==========================================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
