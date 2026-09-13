from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


# ============================================================
# BASE DIRECTORY / ENVIRONMENT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(
    BASE_DIR / ".env"
)


def env_bool(
    name: str,
    default: bool = False,
) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }


def env_list(
    name: str,
    default: list[str] | None = None,
) -> list[str]:
    value = os.getenv(name)

    if value is None:
        return default or []

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


# ============================================================
# SECURITY
# ============================================================

DEBUG = env_bool(
    "DEBUG",
    True,
)

SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "",
).strip()

if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = (
            "django-development-only-secret-key-"
            "change-this-before-production"
        )
    else:
        raise RuntimeError(
            "DJANGO_SECRET_KEY must be configured "
            "when DEBUG=False."
        )


# ============================================================
# HOSTS
# ============================================================

DEFAULT_ALLOWED_HOSTS = [
    "127.0.0.1",
    "localhost",
]

ALLOWED_HOSTS = env_list(
    "ALLOWED_HOSTS",
    DEFAULT_ALLOWED_HOSTS,
)


# ============================================================
# APPLICATIONS
# ============================================================

INSTALLED_APPS = [
    # --------------------------------------------------------
    # Django
    # --------------------------------------------------------

    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # --------------------------------------------------------
    # Third-party
    # --------------------------------------------------------

    "rest_framework",
    "corsheaders",
    "rest_framework_simplejwt.token_blacklist",

    # --------------------------------------------------------
    # Project
    # --------------------------------------------------------

    "accounts",
    "threat_detection",
    "phishing",
    "impersonation",
    "anomaly_detection",
    "incidents",
    "audit_logs",
]


# ============================================================
# MIDDLEWARE
# ============================================================

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


# ============================================================
# URL CONFIGURATION
# ============================================================

ROOT_URLCONF = "config.urls"


# ============================================================
# TEMPLATES
# ============================================================

TEMPLATES = [
    {
        "BACKEND": (
            "django.template.backends.django.DjangoTemplates"
        ),
        "DIRS": [
            BASE_DIR / "templates",
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                (
                    "django.template.context_processors.request"
                ),
                (
                    "django.contrib.auth.context_processors.auth"
                ),
                (
                    "django.contrib.messages.context_processors.messages"
                ),
            ],
        },
    },
]


# ============================================================
# WSGI / ASGI
# ============================================================

WSGI_APPLICATION = "config.wsgi.application"

ASGI_APPLICATION = "config.asgi.application"


# ============================================================
# DATABASE
# ============================================================

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# ============================================================
# PASSWORD VALIDATION
# ============================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "MinimumLengthValidator"
        ),
        "OPTIONS": {
            "min_length": 12,
        },
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "CommonPasswordValidator"
        ),
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "NumericPasswordValidator"
        ),
    },
]


# ============================================================
# CUSTOM USER MODEL
# ============================================================

AUTH_USER_MODEL = "accounts.User"


# ============================================================
# INTERNATIONALIZATION
# ============================================================

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Asia/Kolkata"

USE_I18N = True

USE_TZ = True


# ============================================================
# STATIC FILES
# ============================================================

STATIC_URL = "static/"

STATIC_ROOT = BASE_DIR / "staticfiles"


# ============================================================
# MEDIA FILES
# ============================================================

MEDIA_URL = "/media/"

MEDIA_ROOT = BASE_DIR / "media"


# ============================================================
# DEFAULT PRIMARY KEY
# ============================================================

DEFAULT_AUTO_FIELD = (
    "django.db.models.BigAutoField"
)


# ============================================================
# DJANGO REST FRAMEWORK
# ============================================================

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication."
        "JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ),
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/hour",
        "user": "600/hour",
    },
}


# ============================================================
# JWT CONFIGURATION
# ============================================================

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(
        minutes=int(
            os.getenv(
                "JWT_ACCESS_MINUTES",
                "30",
            )
        )
    ),
    "REFRESH_TOKEN_LIFETIME": timedelta(
        days=int(
            os.getenv(
                "JWT_REFRESH_DAYS",
                "1",
            )
        )
    ),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "AUTH_HEADER_TYPES": (
        "Bearer",
    ),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "JTI_CLAIM": "jti",
    "ALGORITHM": "HS256",
    "SIGNING_KEY": os.getenv(
        "JWT_SIGNING_KEY",
        SECRET_KEY,
    ).strip(),
}


# ============================================================
# CORS
# ============================================================

if DEBUG:

    CORS_ALLOW_ALL_ORIGINS = env_bool(
        "CORS_ALLOW_ALL_ORIGINS",
        True,
    )

else:

    CORS_ALLOW_ALL_ORIGINS = False

    CORS_ALLOWED_ORIGINS = env_list(
        "CORS_ALLOWED_ORIGINS",
        [],
    )


# ============================================================
# CSRF TRUSTED ORIGINS
# ============================================================

CSRF_TRUSTED_ORIGINS = env_list(
    "CSRF_TRUSTED_ORIGINS",
    [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
)


# ============================================================
# PROXY / CLIENT IP
# ============================================================

TRUST_PROXY_HEADERS = env_bool(
    "TRUST_PROXY_HEADERS",
    False,
)


# ============================================================
# SECURITY HEADERS
# ============================================================

SECURE_CONTENT_TYPE_NOSNIFF = True

X_FRAME_OPTIONS = "DENY"

SECURE_REFERRER_POLICY = "same-origin"

SECURE_CROSS_ORIGIN_OPENER_POLICY = (
    "same-origin"
)


# ============================================================
# HTTPS SECURITY
# ============================================================

if DEBUG:

    SECURE_SSL_REDIRECT = False

    SESSION_COOKIE_SECURE = False

    CSRF_COOKIE_SECURE = False

    SECURE_HSTS_SECONDS = 0

    SECURE_HSTS_INCLUDE_SUBDOMAINS = False

    SECURE_HSTS_PRELOAD = False

else:

    SECURE_SSL_REDIRECT = env_bool(
        "SECURE_SSL_REDIRECT",
        True,
    )

    SESSION_COOKIE_SECURE = True

    CSRF_COOKIE_SECURE = True

    SECURE_HSTS_SECONDS = int(
        os.getenv(
            "SECURE_HSTS_SECONDS",
            "31536000",
        )
    )

    SECURE_HSTS_INCLUDE_SUBDOMAINS = True

    SECURE_HSTS_PRELOAD = True


# ============================================================
# SESSION SECURITY
# ============================================================

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_HTTPONLY = False

CSRF_COOKIE_SAMESITE = "Lax"


# ============================================================
# FILE UPLOAD SECURITY
# ============================================================

FILE_UPLOAD_MAX_MEMORY_SIZE = (
    10 * 1024 * 1024
)

DATA_UPLOAD_MAX_MEMORY_SIZE = (
    20 * 1024 * 1024
)


# ============================================================
# AI / RISK ENGINE
# ============================================================

AI_RISK_LEVELS = {
    "SAFE": (
        0,
        19,
    ),
    "LOW": (
        20,
        39,
    ),
    "MEDIUM": (
        40,
        59,
    ),
    "HIGH": (
        60,
        79,
    ),
    "CRITICAL": (
        80,
        100,
    ),
}


# ============================================================
# CLOUDFLARE TURNSTILE
# ============================================================

TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    "",
).strip()


# ============================================================
# LOGIN / LOGOUT
# ============================================================

LOGIN_URL = "/api/auth/login/"

LOGOUT_REDIRECT_URL = None


# ============================================================
# LOGIN RATE LIMIT / LOCKOUT
# ============================================================

LOGIN_MAX_ATTEMPTS = int(
    os.getenv(
        "LOGIN_MAX_ATTEMPTS",
        "5",
    )
)

LOGIN_WINDOW_SECONDS = int(
    os.getenv(
        "LOGIN_WINDOW_SECONDS",
        str(15 * 60),
    )
)

LOGIN_LOCKOUT_SECONDS = int(
    os.getenv(
        "LOGIN_LOCKOUT_SECONDS",
        str(15 * 60),
    )
)


# ============================================================
# CACHE
# ============================================================

CACHE_BACKEND = os.getenv(
    "CACHE_BACKEND",
    "django.core.cache.backends.locmem.LocMemCache",
).strip()

if CACHE_BACKEND.endswith(
    "DatabaseCache"
):

    CACHES = {
        "default": {
            "BACKEND": CACHE_BACKEND,
            "LOCATION": os.getenv(
                "CACHE_LOCATION",
                "guard-cache",
            ),
            "TIMEOUT": None,
        }
    }

else:

    CACHES = {
        "default": {
            "BACKEND": CACHE_BACKEND,
            "LOCATION": os.getenv(
                "CACHE_LOCATION",
                "guard-local-cache",
            ),
        }
    }


# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO",
).upper()

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "standard": {
            "format": (
                "{levelname} {asctime} "
                "{name} {message}"
            ),
            "style": "{",
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
    },

    "loggers": {
        "django": {
            "handlers": [
                "console",
            ],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "guard": {
            "handlers": [
                "console",
            ],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}
