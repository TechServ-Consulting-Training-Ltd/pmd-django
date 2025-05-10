import json

from django.test import TestCase, RequestFactory
from django.views.decorators.http import require_POST
from testapp.models import TestModel, TestRelatedModel, UniqueModel
from pmd_django.api import api


@require_POST
@api({
    "code": {"type": "string", "required": True, "empty": False},
})
def create_unique_view(request):
    related = TestRelatedModel.objects.first()
    return UniqueModel.objects.create(code=request.json["code"], related=related)


class TestJsonDecoratorWithRelations(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()

        test_model = TestModel.objects.create(status="linked")
        cls.related = TestRelatedModel.objects.create(name="Related Obj", related=test_model)


    def test_nested_relationships_are_serialized(self):
        request = self.factory.post(
            "/",
            data=json.dumps({"code": "XYZ"}),
            content_type="application/json",
        )
        response = create_unique_view(request)

        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)

        self.assertIn("code", data)
        self.assertEqual(data["code"], "XYZ")

        self.assertIn("related", data)
        self.assertIsInstance(data["related"], dict)
        self.assertEqual(data["related"]["name"], "Related Obj")

        self.assertIn("related", data["related"])
        self.assertEqual(data["related"]["related"]["status"], "linked")


    def test_rejects_fields_not_in_schema(self):
        request = self.factory.post(
            "/",
            data=json.dumps({
                "code": "SHOULD_FAIL",
                "id": 999,
                "unvalidated_field": "should be rejected"
            }),
            content_type="application/json",
        )

        response = create_unique_view(request)
        self.assertEqual(response.status_code, 400)

        data = json.loads(response.content)

        self.assertIn("errors", data)
        self.assertIn("id", data["errors"])
        self.assertIn("unvalidated_field", data["errors"])


    def test_rejects_empty_string_by_default_for_required_string(self):
        request = self.factory.post(
            "/",
            data=json.dumps({"code": ""}),
            content_type="application/json",
        )
        response = create_unique_view(request)

        self.assertEqual(response.status_code, 400)

        data = json.loads(response.content)
        self.assertIn("errors", data)
        self.assertIn("code", data["errors"])
        self.assertEqual(data["errors"]["code"], ["empty values not allowed"])