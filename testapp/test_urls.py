import unittest
from django.urls import path, include

from pmd_django.management.commands.urls import route_to_key, route_to_value, extract_routes


def dummy_view(request): pass


class TestGeneratedUrlsHelpers(unittest.TestCase):
    def test_route_to_key_static(self):
        self.assertEqual(route_to_key("/dashboard/get_permits"), "DASHBOARD_GET_PERMITS")
        self.assertEqual(route_to_key("/pm-tracker/bulk_update_tags"), "PM_TRACKER_BULK_UPDATE_TAGS")
        self.assertEqual(route_to_key(""), "ROOT")
        self.assertEqual(route_to_key("/permit/<int:permit_id>/workflow"), "PERMIT_PERMIT_ID_WORKFLOW")

    def test_route_to_key_weird_chars(self):
        self.assertEqual(route_to_key("/crazy-Route/<uuid:abc>/yo!"), "CRAZY_ROUTE_ABC_YO")

    def test_route_to_value_static(self):
        self.assertEqual(
            route_to_value("/dashboard/get_permits"),
            '"/dashboard/get_permits"'
        )

    def test_route_to_value_dynamic_single(self):
        self.assertEqual(
            route_to_value("/permit/<int:permit_id>/workflow"),
            "(permit_id: string | number) => `/permit/${permit_id}/workflow`"
        )

    def test_route_to_value_dynamic_multi(self):
        self.assertEqual(
            route_to_value("/a/<int:x>/b/<slug:y>/c"),
            "(x: string | number, y: string | number) => `/a/${x}/b/${y}/c`"
        )

    def test_extract_routes_simple(self):
        urlpatterns = [
            path("dashboard/get_permits", dummy_view),
            path("permit/<int:permit_id>/workflow", dummy_view),
        ]
        result = extract_routes(urlpatterns)
        self.assertIn("dashboard/get_permits", result)
        self.assertIn("permit/<int:permit_id>/workflow", result)

    def test_extract_routes_nested(self):
        urlpatterns = [
            path("outer/", include([
                path("inner/", dummy_view),
                path("deep/<int:item_id>/view", dummy_view),
            ])),
        ]
        result = extract_routes(urlpatterns)
        self.assertIn("outer/inner/", result)
        self.assertIn("outer/deep/<int:item_id>/view", result)
