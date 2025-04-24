from django.conf import settings
from django.test import TestCase
from pmd_django.auth import generate_identity


class BaseAuthTestCase(TestCase):
    def setUp(self):
        identity = {
            "email": "dev@techserv.com",
            "permissions": [{"resource": "all", "role": "dev"}],
        }
        self.set_signed_identity(identity)

    def set_signed_identity(self, identity: dict):
        public_jwk_b64, signed_identity_token = generate_identity(identity)
        settings.AUTH_PUBLIC_KEY = public_jwk_b64
        self.auth_headers = {"cookie": f"signedIdentity={signed_identity_token}"}
        self.client.cookies.load(self.auth_headers["cookie"])
