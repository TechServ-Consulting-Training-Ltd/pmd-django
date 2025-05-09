import json
from django.http import QueryDict
from pmd_django.generic_table.generic_table import apply_all_filters


def build_filtered_queryset(
        qs,
        payload: dict,
        *,
        field=None,
        counted_values=None,
        extra_filters=None,
        extra_filter_from_request=None,
):
    fake_get = QueryDict("", mutable=True)

    if payload.get("search"):
        fake_get["number"] = payload["search"]
    if payload.get("sortBy"):
        fake_get["sort_by"] = payload["sortBy"]
    if payload.get("sortOrder"):
        fake_get["sort_order"] = payload["sortOrder"]
    if payload.get("stageFilter"):
        fake_get["filter"] = payload["stageFilter"]
    if payload.get("userFilters"):
        fake_get["user_filters"] = json.dumps(payload["userFilters"])

    class FakeRequest:
        GET = fake_get
        headers = {}

    filtered_qs, _ = apply_all_filters(
        qs,
        FakeRequest(),
        field=field,
        counted_values=counted_values,
        extra_filters=extra_filters,
        extra_filter_from_request=extra_filter_from_request,
    )

    return filtered_qs
