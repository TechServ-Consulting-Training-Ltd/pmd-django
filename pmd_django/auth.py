from django.conf import settings
from django.http import HttpRequest, HttpResponse
import base64
from jwcrypto import jwk, jws
from jwcrypto.common import json_decode


def api_key_middleware(get_response):
    def _(request: HttpRequest):
        if request.path.endswith("health") or request.path.endswith("health/"):
            return get_response(request)

        if request.method == "OPTIONS":
            return HttpResponse("Good for preflight")

        signed_identity = request.COOKIES.get("signedIdentity")

        if signed_identity:
            try:
                public_jwk_b64 = getattr(settings, "AUTH_PUBLIC_KEY", None)
                if public_jwk_b64:
                    jwk_json = base64.b64decode(public_jwk_b64).decode("utf-8")
                    key = jwk.JWK.from_json(jwk_json)

                    jws_token = jws.JWS()
                    jws_token.deserialize(signed_identity)
                    jws_token.verify(key)

                    identity = json_decode(jws_token.payload)

                    request.identity = identity
                    for p in identity["permissions"]:
                        if p['resource'] in (settings.APP_NAME, 'all'):
                            return get_response(request)

            except Exception:
                res = HttpResponse("Not authenticated")
                res.status_code = 401
                return res

        res = HttpResponse("Not authenticated")
        res.status_code = 401
        return res

    return _
