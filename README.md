# pmd-django
## dev
Provides the Django management command `python manage.py dev`

## auth middleware
To use the auth middleware:
1. List `pmd_django` in the INSTALLED_APPS in `settings.py`
```python
INSTALLED_APPS = [
    "pmd_django",
    ...
]
```
2. List `pmd_django.auth.api_key_middleware` in the MIDDLEWARE just underneath
`django.contrib.auth.middleware.AuthenticationMiddleware`
```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "pmd_django.auth.api_key_middleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
```
3. Optionally add `USER_API_KEY = env.str("USER_API_KEY")` to `settings.py`
4. Optionally add `USER_AUTH_FILTERS` to `settings.py`. This should be a list of
functions that will get passed a `request` object. The function should return true if the
middleware should authorize the `request`.

## Testing
Run `python manage.py test` from the root of the project to run the tests.
