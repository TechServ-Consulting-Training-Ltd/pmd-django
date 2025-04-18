import base64
import json
from django.test import TestCase, RequestFactory, override_settings
from django.http import JsonResponse
from pmd_django.auth import api_key_middleware, generate_identity

identity = {"email": "dev@techserv.com", "permissions": [{"resource": "all", "role": "dev"}]}
(public_jwk_b64, signed_token) = generate_identity(identity)
payload = json.dumps(identity)

@override_settings(AUTH_PUBLIC_KEY=public_jwk_b64)
class TestAuthMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

        def dummy_view(request):
            return JsonResponse(request.identity)

        self.middleware = api_key_middleware(dummy_view)

    def test_valid_signed_permissions(self):
        request = self.factory.get("/")
        request.COOKIES["signedIdentity"] = signed_token

        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)

        self.assertEqual(data, identity)

    def test_invalid_signature(self):
        request = self.factory.get("/")
        request.COOKIES["signedIdentity"] = "bad.token.value"

        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)

    def test_missing_cookies(self):
        request = self.factory.get("/")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)
