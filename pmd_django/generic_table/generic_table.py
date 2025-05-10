import io
import json
import operator
from datetime import datetime

from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.db.models import Count, Q
from django.http import FileResponse, JsonResponse
from openpyxl.workbook import Workbook

COMMON_RESPONSE_DEFAULTS = {
    "ordering": "-id",
    "page_size": 30,
}


def _build_counts(qs, status_field, counted_values):
    counts = {key: 0 for key in counted_values}
    total = 0
    for row in qs.values(status_field).annotate(count=Count(status_field)):
        counts[row[status_field]] = row["count"]
        total += row["count"]
    counts["ALL"] = total
    return counts


def _get_page_size(request, page_size):
    try:
        return int(
            request.GET.get(
                "page_size", page_size or COMMON_RESPONSE_DEFAULTS["page_size"]
            )
        )
    except (ValueError, TypeError):
        return COMMON_RESPONSE_DEFAULTS["page_size"]


def _apply_filters(qs, request, extra_filters=None, extra_filter_from_request=None):
    if extra_filters:
        qs = qs.filter(extra_filters)
    if extra_filter_from_request:
        for param, lookup in extra_filter_from_request.items():
            value = request.GET.get(param)
            if value:
                qs = qs.filter(**{lookup: value})
    return qs


def _get_allowed_fields(qs):
    model = qs.model

    # Get direct fields from the model
    allowed_fields = {f.name for f in model._meta.get_fields() if hasattr(f, "attname")}

    # ForeignKey, OneToOneField, etc.
    related_fields = {
        f.name for f in model._meta.get_fields() if f.is_relation and f.related_model
    }

    # Allow filtering on related fields using `related_model__field` notation
    for rel_field in related_fields:
        related_model = model._meta.get_field(rel_field).related_model
        if related_model:
            allowed_fields.update(
                {
                    f"{rel_field}__{f.name}"
                    for f in related_model._meta.get_fields()
                    if hasattr(f, "attname")
                }
            )

    # Detect dynamically added fields from QuerySet (e.g., .annotate() or .values())
    if hasattr(qs, "_fields") and qs._fields:  # .values() fields
        allowed_fields.update(qs._fields)

    if hasattr(qs, "query") and hasattr(qs.query, "annotations"):  # .annotate() fields
        allowed_fields.update(qs.query.annotations.keys())

    if hasattr(qs, "extra_allowed_fields"):
        allowed_fields.update(qs.extra_allowed_fields)

    return allowed_fields


def _apply_user_filters(qs, request):
    user_filters = request.GET.get("user_filters")
    if not user_filters:
        return qs

    ALLOWED_FIELDS = _get_allowed_fields(qs)
    ALLOWED_CONDITIONS = {
        "exact",
        "iexact",
        "contains",
        "icontains",
        "gt",
        "gte",
        "lt",
        "lte",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "range",
        "isnull",
        "in",
        "exclude",
    }

    try:
        filters = json.loads(user_filters)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON in user_filters")

    operators = []
    queries = []

    for index, f in enumerate(filters):
        field = f.get("field")
        condition = f.get("condition")
        value = f.get("value")

        if not field or not condition or value in [None, ""]:
            continue

        if field not in ALLOWED_FIELDS:
            raise ValueError(f"Filtering on '{field}' is not allowed")

        if condition not in ALLOWED_CONDITIONS:
            raise ValueError(f"Condition '{condition}' is not supported")

        lookup_expression = f"{field}__{condition}"
        queries.append(Q(**{lookup_expression: value}))

        if index > 0 and f.get("logicalOperator"):
            operators.append(
                {
                    "AND": operator.and_,
                    "OR": operator.or_,
                    "AND NOT": lambda a, b: operator.and_(a, operator.inv(b)),
                    "OR NOT": lambda a, b: operator.or_(a, operator.inv(b)),
                }.get(f["logicalOperator"], operator.and_)  # Default to AND if invalid
            )

    if not queries:
        return qs

    if len(operators) != len(queries) - 1:
        raise ValueError(
            f"Filter-operator mismatch: expected {len(queries) - 1} operators, got {len(operators)}"
        )

    accumulator = queries[0]
    for q, op in zip(queries[1:], operators, strict=True):  # Ensures exact match
        accumulator = op(accumulator, q)

    return qs.filter(accumulator)


def _apply_ordering(qs, request):
    sort_by = request.GET.get("sort_by", "id")
    sort_order = request.GET.get("sort_order", "asc")
    ordering = f"-{sort_by}" if sort_order == "desc" else sort_by
    return qs.order_by(ordering or COMMON_RESPONSE_DEFAULTS.get("ordering", "id"))


def _paginate_queryset(qs, request, page_size):
    paginator = Paginator(qs, page_size)
    page = request.GET.get("page", 1)
    try:
        page_obj = paginator.page(page)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)

    return page_obj, paginator


def apply_all_filters(
    qs,
    request,
    field=None,
    counted_values=None,
    extra_filters=None,
    extra_filter_from_request=None,
):
    qs = _apply_user_filters(qs, request)

    qs = _apply_filters(qs, request, extra_filters, extra_filter_from_request)

    counts = None
    if field is not None and counted_values is not None:
        counts = _build_counts(qs, field, counted_values)

    if field is not None and (status_value := request.GET.get("filter")):
        qs = qs.filter(**{field: status_value})  # Domain logic filter

    return qs, counts


def paginate_queryset(qs, request, page_size=None):
    page_size = _get_page_size(request, page_size)
    return _paginate_queryset(qs, request, page_size)

def _sanitize_cell_value(value):
    if isinstance(value, list):
        return ", ".join(map(str, value))
    elif isinstance(value, dict):
        return json.dumps(value)
    elif isinstance(value, datetime) and value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value

def _generate_download_response(qs, values_list, transform=None):
    wb = Workbook()
    worksheet = wb.active
    worksheet.title = "Exported Data"

    if transform:
        data = transform(qs)
    else:
        fields = values_list or getattr(qs, "extra_allowed_fields", [])
        data = list(qs.values(*fields))

    if not data:
        worksheet.append(["No data"])
    else:
        headers = list(data[0].keys())
        worksheet.append(headers)
        for row in data:
            worksheet.append([_sanitize_cell_value(row.get(field)) for field in headers])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return FileResponse(
        output,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        filename="export.xlsx",
    )


def view(
    qs,
    request,
    field=None,
    counted_values=None,
    extra_filters=None,
    extra_filter_from_request=None,
    values_list=None,
    data_key="data",
    page_size=None,
    transform=None,
    final_json_hook=None,
) -> JsonResponse | FileResponse:
    qs.extra_allowed_fields = values_list if values_list is not None else []

    qs, counts = apply_all_filters(
        qs, request, field, counted_values, extra_filters, extra_filter_from_request
    )

    qs = _apply_ordering(qs, request)

    accept_header = request.headers.get("Accept", "")
    is_excel = (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        in accept_header
    )
    if is_excel:
        return _generate_download_response(qs, values_list, transform=transform)

    page_obj, paginator = paginate_queryset(qs, request, page_size)

    if transform:
        data = transform(page_obj)
    else:
        data = list(page_obj.object_list.values(*values_list)) if values_list else [
            {field.name: getattr(obj, field.name) for field in obj._meta.fields}
            for obj in page_obj.object_list
        ]

    return_data = {
        "stages": list(counts.keys()) if counts else [],
        "stageCounts": counts if counts else {},
        data_key: data,
        "pagination": {
            "current_page": page_obj.number,
            "total_pages": paginator.num_pages,
            "total_items": paginator.count,
            "has_next": page_obj.has_next(),
            "has_previous": page_obj.has_previous(),
        },
    }

    if final_json_hook:
        return_data = final_json_hook(return_data)

    return JsonResponse(return_data)
