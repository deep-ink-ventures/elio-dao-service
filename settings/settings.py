"""
For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

import os
import sys
from datetime import timedelta
from pathlib import Path

from corsheaders.defaults import default_headers

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "dev-only-key"
CONFIG_SECRET = os.environ.get("CONFIG_SECRET")

ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",")

# Application definition
INSTALLED_APPS = [
    "daphne",
    "django_extensions",
    "rest_framework",
    "drf_yasg",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "core.apps.CoreConfig",
    "multiclique.apps.MulticliqueConfig",
]

MIDDLEWARE = [
    "core.middleware.HealthCheckMiddleware",
    "core.middleware.BlockMetadataMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_HEADERS = list(default_headers) + ["signature", "block-number", "block-hash"]
CORS_EXPOSE_HEADERS = ["signature", "block-number", "block-hash"]
ROOT_URLCONF = "service.urls"
WSGI_APPLICATION = "service.wsgi.application"
ASGI_APPLICATION = "service.asgi.application"
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000")

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Cache
# https://docs.djangoproject.com/en/4.1/topics/cache/
redis = f"redis://{os.environ.get('REDIS_HOST', '0.0.0.0')}:{os.environ.get('REDIS_PORT', '6379')}"
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": f"{redis}/1",
        "TIMEOUT": None,
    },
}

# Celery
CELERY_BROKER_TRANSPORT = "redis"
CELERY_BROKER_URL = f"{redis}/2"
CELERY_BROKER_TRANSPORT_OPTIONS = {"fanout_prefix": True}
CELERY_RESULT_BACKEND = None
CELERY_REDIS_MAX_CONNECTIONS = 256
CELERY_ACCEPT_CONTENT = ["json", "pickle"]

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DATABASE_NAME", "core"),
        "USER": os.environ.get("DATABASE_USER", "postgres"),
        "PASSWORD": os.environ.get("DATABASE_PASSWORD", "postgres"),
        "HOST": os.environ.get("DATABASE_HOST", "0.0.0.0"),
        "PORT": os.environ.get("DATABASE_PORT", "5432"),
    },
}

LOG_LEVEL = os.environ.get("LOG_LEVEL", "info").upper()

SLACK_DEFAULT_URL = os.environ.get("SLACK_DEFAULT_URL")
SLACK_ELIO_URL = os.environ.get("SLACK_ELIO_URL")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "slack": {"class": "core.management.logger.slack.SlackHandler"},
        "console": {"class": "logging.StreamHandler"},
    },
    "loggers": {
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": True,
        },
        "alerts": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": True,
        },
        "alerts.slack": {
            "handlers": ["slack"],
            "level": LOG_LEVEL,
            "propagate": True,
        },
    },
}

# Rest Framework
# http://www.django-rest-framework.org/
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ("rest_framework_simplejwt.authentication.JWTStatelessUserAuthentication",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "DEFAULT_PARSER_CLASSES": ("rest_framework.parsers.JSONParser",),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.AllowAny",),
    "PAGE_SIZE": 10,
    "DEFAULT_THROTTLE_RATES": {
        "user": "5/hour",
    },
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "SIGNING_KEY": SECRET_KEY,
    "USER_ID_FIELD": "address",
    "ROTATE_REFRESH_TOKENS": True,
}

# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/
STATICFILES_FINDERS = [
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
]
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "static"

# when using default s3 upload these have to be set
AWS_STORAGE_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME")
AWS_S3_ACCESS_KEY_ID = os.environ.get("AWS_S3_ACCESS_KEY_ID")
AWS_S3_SECRET_ACCESS_KEY = os.environ.get("AWS_S3_SECRET_ACCESS_KEY")
AWS_REGION = os.environ.get("AWS_REGION")

CHALLENGE_LIFETIME = 60  # seconds

# storage
FILE_UPLOAD_CLASS = os.environ.get("FILE_UPLOAD_CLASS", "core.file_handling.local.storage")
ENCRYPTION_ALGORITHM = os.environ.get("ENCRYPTION_ALGORITHM", "sha3_256")
MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"
MAX_LOGO_SIZE = int(os.environ.get("MAX_LOGO_SIZE", 2_000_000))  # 2mb
LOGO_SIZES = {
    "small": (88, 88),
    "medium": (104, 104),
    "large": (124, 124),
}

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# soroban
CORE_CONTRACT_ADDRESS = os.environ.get("CORE_CONTRACT")
VOTES_CONTRACT_ADDRESS = os.environ.get("VOTES_CONTRACT")
MULTICLIQUE_CONTRACT_ADDRESS = os.environ.get("MULTICLIQUE_CONTRACT_ADDRESS")
POLICY_CONTRACT_ADDRESS = os.environ.get("POLICY_CONTRACT_ADDRESS")
ASSETS_WASM_HASH = os.environ.get("ASSETS_WASM_HASH")
SOROBAN_START_LEDGER = 600_000
BLOCKCHAIN_URL = os.environ.get("BLOCKCHAIN_URL")
NETWORK_PASSPHRASE = os.environ.get("NETWORK_PASSPHRASE")
BLOCK_CREATION_INTERVAL = int(os.environ.get("BLOCK_CREATION_INTERVAL", 5))  # seconds
RETRY_DELAYS = [int(_) for _ in os.environ.get("RETRY_DELAYS", "5,10,30,60,120").split(",")]
DEPOSIT_TO_CREATE_DAO = 10_000_000_000
DEPOSIT_TO_CREATE_PROPOSAL = 100_000
TYPE_REGISTRY_PRESET = "polkadot"

SWAGGER_SETTINGS = {
    "DEFAULT_FIELD_INSPECTORS": [
        "core.swagger.Base64ImageFieldInspector",
        "drf_yasg.inspectors.CamelCaseJSONFilter",
        "drf_yasg.inspectors.ReferencingSerializerInspector",
        "drf_yasg.inspectors.RelatedFieldInspector",
        "drf_yasg.inspectors.ChoiceFieldInspector",
        "drf_yasg.inspectors.FileFieldInspector",
        "drf_yasg.inspectors.DictFieldInspector",
        "drf_yasg.inspectors.JSONFieldInspector",
        "drf_yasg.inspectors.HiddenFieldInspector",
        "drf_yasg.inspectors.RecursiveFieldInspector",
        "drf_yasg.inspectors.SerializerMethodFieldInspector",
        "drf_yasg.inspectors.SimpleFieldInspector",
        "drf_yasg.inspectors.StringDefaultFieldInspector",
    ],
    "DEFAULT_PAGINATOR_INSPECTORS": [
        "core.swagger.PaginationInspector",
        "drf_yasg.inspectors.CoreAPICompatInspector",
    ],
    "SECURITY_DEFINITIONS": {
        "Basic": {
            "type": "allow any",
        },
        "Signature": {
            "name": "Signature",
            "in": "header",
            "type": "Signature in Header",
        },
        "Bearer": {
            "name": "Authorization",
            "in": "header",
            "type": "JWT Token in Header",
        },
    },
}

APPLICATION_STAGE = os.environ.get("APPLICATION_STAGE", "development")
DEBUG = APPLICATION_STAGE == "development"

if APPLICATION_STAGE == "development":
    from .dev import *  # noqa: F401,F403

if APPLICATION_STAGE == "production":
    from .prod import *  # noqa: F401,F403

if "test" in sys.argv:
    from .testing import *  # noqa: F401,F403
