from django.test import TestCase
from testapp.models import TestModel
from pmd_django.query_helpers import build_filtered_queryset


class TestBuildFilteredQueryset(TestCase):
    @classmethod
    def setUpTestData(cls):
        TestModel.objects.bulk_create([
            TestModel(status="active"),
            TestModel(status="inactive"),
            TestModel(status="active"),
            TestModel(status="pending"),
        ])

    def test_filters_by_search(self):
        qs = TestModel.objects.all()
        payload = {
            "search": "act",
        }
        filtered = build_filtered_queryset(
            qs,
            payload,
            extra_filter_from_request={"number": "status__icontains"},
        )
        self.assertTrue(all("act" in obj.status for obj in filtered))

    def test_stage_filter_applied(self):
        qs = TestModel.objects.all()
        payload = {
            "stageFilter": "pending"
        }
        filtered = build_filtered_queryset(qs, payload, field="status", counted_values=["active", "inactive", "pending"])
        self.assertEqual(list(filtered.values_list("status", flat=True)), ["pending"])

    def test_user_filters_applied(self):
        qs = TestModel.objects.all()
        payload = {
            "userFilters": [
                {"field": "status", "condition": "exact", "value": "active"},
            ]
        }
        filtered = build_filtered_queryset(qs, payload)
        statuses = list(filtered.values_list("status", flat=True))
        self.assertEqual(statuses, ["active", "active"])
