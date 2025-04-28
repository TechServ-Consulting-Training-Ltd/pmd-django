import json

from django.http import JsonResponse
from django.test import TestCase, RequestFactory, override_settings

from pmd_django.auth import api_key_middleware, generate_identity

identity = {"email": "dev@techserv.com", "permissions": [{"resource": "all", "role": "dev"}]}
(public_jwk_b64, signed_token) = generate_identity(identity)
payload = json.dumps(identity)

@override_settings(AUTH_PUBLIC_KEY=public_jwk_b64)
class TestAuthMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

        def dummy_view(request):
            return JsonResponse(request.identity if hasattr(request, "identity") else {})

        self.middleware = api_key_middleware(dummy_view)

    def test_valid_signed_permissions_cookie(self):
        request = self.factory.get("/")
        request.COOKIES["signedIdentity"] = signed_token

        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data, identity)

    def test_valid_signed_permissions_header(self):
        request = self.factory.get("/", HTTP_SIGNED_IDENTITY=signed_token)

        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data, identity)

    def test_invalid_signature_cookie(self):
        request = self.factory.get("/")
        request.COOKIES["signedIdentity"] = "bad.token.value"

        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)

    def test_invalid_signature_header(self):
        request = self.factory.get("/", HTTP_SIGNED_IDENTITY="bad.token.value")

        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)

    def test_missing_cookies_and_headers(self):
        request = self.factory.get("/")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)

    def test_logout_bypasses_auth(self):
        request = self.factory.post("/logout")
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)
