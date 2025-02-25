from django.conf import settings
from django.http import HttpRequest, HttpResponse


def api_key_middleware(get_response):
    def _(request: HttpRequest):
        request.current_user = request.headers.get("TS-USER", "system")

        if settings.DEBUG:
            return get_response(request)

        # Exclude health checks
        if request.path.endswith("health") or request.path.endswith("health/"):
            return get_response(request)

        if request.method == "OPTIONS":
            return HttpResponse("Good for preflight")

        user_filters = None
        try:
            user_filters = settings.USER_AUTH_FILTERS
        except AttributeError:
            pass

        if user_filters is not None:
            for f in user_filters:
                if f(request):
                    return get_response(request)

        user_api_key = None
        try:
            user_api_key = settings.USER_API_KEY
        except AttributeError:
            pass

        if user_api_key is not None:
            if request.headers.get("Authorization") == f"Bearer {settings.USER_API_KEY}":
                return get_response(request)

        res = HttpResponse("Not authenticated")
        res.status_code = 401
        return res

    return _
