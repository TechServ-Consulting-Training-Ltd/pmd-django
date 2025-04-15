import base64
import json
from django.test import TestCase, RequestFactory, override_settings
from django.http import JsonResponse
from jwcrypto import jwk, jws
from pmd_django.auth import api_key_middleware

permissions = {"permissions": [{"resource": "all", "role": "dev"}]}
payload = json.dumps(permissions)

key = jwk.JWK.generate(kty="OKP", crv="Ed25519")
public_jwk_b64 = base64.b64encode(key.export_public().encode("utf-8")).decode("utf-8")

signed = jws.JWS(payload.encode("utf-8"))
signed.add_signature(key, None, protected=json.dumps({"alg": "EdDSA"}))
signed_token = signed.serialize(compact=True)

@override_settings(AUTH_PUBLIC_KEY=public_jwk_b64)
class TestAuthMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

        def dummy_view(request):
            return JsonResponse({
                "current_user": getattr(request, "current_user", None),
                "permissions": getattr(request, "user_permissions", None),
            })

        self.middleware = api_key_middleware(dummy_view)

    def test_valid_signed_permissions(self):
        request = self.factory.get("/")
        request.COOKIES["signedPermissions"] = signed_token
        request.COOKIES["permissions"] = payload
        request.COOKIES["email"] = "dev@example.com"

        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)

        self.assertEqual(data["current_user"], "dev@example.com")
        self.assertEqual(data["permissions"], permissions)

    def test_invalid_signature(self):
        request = self.factory.get("/")
        request.COOKIES["signedPermissions"] = "bad.token.value"
        request.COOKIES["permissions"] = payload
        request.COOKIES["email"] = "dev@example.com"

        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)

    def test_missing_cookies(self):
        request = self.factory.get("/")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)
