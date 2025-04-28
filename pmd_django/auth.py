import json

from django.conf import settings
from django.http import HttpRequest, HttpResponse
import base64
from jwcrypto import jwk, jws
from jwcrypto.common import json_decode


def api_key_middleware(get_response):
    def _(request: HttpRequest):
        if request.path.endswith("health") or request.path.endswith("health/"):
            return get_response(request)

        if request.path.endswith("identity") or request.path.endswith("identity/"):
            # This is for local dev, in non-local API-Gateway maps this to a header.
            signed_identity = request.COOKIES.get("signedIdentity")
            if not signed_identity:
                # API Gateway.
                signed_identity = request.META.get("HTTP_SIGNED_IDENTITY")

            if not signed_identity:
                return HttpResponse("Missing signedIdentity", status=401)

            return get_response(request)

        if request.path.endswith(("logout", "logout/")):
            return get_response(request)

        if request.method == "OPTIONS":
            return HttpResponse("Good for preflight")

        signed_identity = request.COOKIES.get("signedIdentity") or request.META.get("HTTP_SIGNED_IDENTITY")

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

def generate_identity(payload: dict):
    """Generates a signed identity for the given payload: {"email": "dev@techserv.com", "permissions": [{"resource": "all", "role": "dev"}]}"""
    payload = json.dumps(payload)
    private_jwk = jwk.JWK.generate(kty="OKP", crv="Ed25519")
    public_jwk_b64 = base64.b64encode(private_jwk.export_public().encode("utf-8")).decode("utf-8")

    signed = jws.JWS(payload.encode("utf-8"))
    signed.add_signature(private_jwk, None, protected=json.dumps({"alg": "EdDSA"}))

    return public_jwk_b64, signed.serialize(compact=True)
