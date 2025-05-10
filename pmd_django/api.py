import json
import re
from functools import wraps
from django.forms.models import model_to_dict
from django.http import JsonResponse, HttpResponse
from django.db import IntegrityError
from django.db.models import Model
from cerberus import Validator


def _model_to_dict_recursive(instance, visited=None):
    if not isinstance(instance, Model):
        return instance

    if visited is None:
        visited = set()

    key = (instance.__class__, instance.pk)
    if key in visited:
        return instance.pk

    visited.add(key)
    data = model_to_dict(instance)

    for field in instance._meta.get_fields():
        if field.is_relation and field.concrete and not field.many_to_many:
            related = getattr(instance, field.name, None)
            if related is not None:
                data[field.name] = _model_to_dict_recursive(related, visited)

    return data


def _apply_required_string_defaults(rules: dict) -> dict:
    for key, rule in rules.items():
        if (
                rule.get("type") == "string"
                and rule.get("required") is True
                and "empty" not in rule
        ):
            rule["empty"] = False
    return rules


def _parse_json_body(request):
    try:
        return json.loads(request.body), None
    except json.JSONDecodeError:
        return None, JsonResponse(
            {"errors": {"non_field_errors": ["Invalid JSON"]}}, status=400
        )


def _validate_and_clean_data(data, rules: dict):
    rules = _apply_required_string_defaults(rules)
    validator = Validator(rules)
    if not validator.validate(data):
        return None, JsonResponse({"errors": validator.errors}, status=400)
    cleaned = {k: validator.document[k] for k in rules if k in validator.document}
    return cleaned, None


def _handle_integrity_error(error: IntegrityError):
    match = re.search(r"Key \((\w+)\)=\(.+?\) already exists", str(error))
    if match:
        return JsonResponse({"errors": {match.group(1): ["already exists"]}}, status=400)
    return JsonResponse({"errors": {"non_field_errors": ["Integrity error"]}}, status=400)


def _serialize_response(result, status=200):
    if isinstance(result, HttpResponse):
        return result
    if isinstance(result, tuple):
        result, status = result
    if isinstance(result, Model):
        return JsonResponse(_model_to_dict_recursive(result), status=status)
    if isinstance(result, list) and result and isinstance(result[0], Model):
        return JsonResponse(
            [_model_to_dict_recursive(obj) for obj in result],
            safe=False,
            status=status
        )
    return JsonResponse(result, status=status)


def api(rules: dict | None = None):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            data, error_response = _parse_json_body(request)
            if error_response:
                return error_response

            if rules:
                data, error_response = _validate_and_clean_data(data, rules)
                if error_response:
                    return error_response

            request.json = data

            try:
                result = view_func(request, *args, **kwargs)
            except IntegrityError as e:
                return _handle_integrity_error(e)

            return _serialize_response(result)

        return _wrapped_view
    return decorator
