import os
import re
from django.core.management.base import BaseCommand
from django.urls import get_resolver, URLPattern, URLResolver
from django.urls.resolvers import RoutePattern


def extract_routes(urlpatterns, prefix=""):
    routes = []

    for entry in urlpatterns:
        if isinstance(entry, URLPattern) and isinstance(entry.pattern, RoutePattern):
            route = prefix + str(entry.pattern)
            routes.append(route)
        elif isinstance(entry, URLResolver):
            nested_prefix = prefix + str(entry.pattern)
            routes += extract_routes(entry.url_patterns, nested_prefix)

    return routes


def route_to_key(route: str) -> str:
    route = route.strip("/")
    if not route:
        return "ROOT"

    # Convert path params like <int:id> to just "id"
    route = re.sub(r"<[^>:]+:([^>]+)>", r"\1", route)
    route = re.sub(r"<([^>]+)>", r"\1", route)

    # Normalize: replace `/` and `-` with `_`
    key = route.upper().replace("/", "_").replace("-", "_")

    # Strip invalid characters (just in case)
    key = re.sub(r"[^A-Z0-9_]", "", key)

    # Ensure it starts with a letter or underscore
    if not re.match(r"^[A-Z_]", key):
        key = "_" + key

    return key



def route_to_value(route: str) -> str:
    params = re.findall(r"<(?:[^>:]+:)?([^>]+)>", route)
    if not params:
        return f'"{route}"'

    param_str = ", ".join(f"{p}: string | number" for p in params)
    path_str = re.sub(r"<(?:[^>:]+:)?([^>]+)>", r"${\1}", route)
    return f"({param_str}) => `{path_str}`"


class Command(BaseCommand):
    help = "Export Django URL patterns as a TypeScript file"

    def add_arguments(self, parser):
        parser.add_argument(
            "--output",
            default="frontend/src/urls.ts",
            help="Path to output TypeScript file",
        )

    def handle(self, *args, **options):
        resolver = get_resolver()
        all_routes = extract_routes(resolver.url_patterns)

        filtered_routes = [
            r for r in all_routes
            if not r.startswith("/admin")
               and not r.startswith("static/")
               and not r.startswith("__debug__")
        ]

        output_lines = [
            "// NO EDIT: Generated via `python manage.py urls`\n\n",
            "export const URLS = {\n"
        ]
        for route in sorted(filtered_routes):
            key = route_to_key(route)
            value = route_to_value(route)
            output_lines.append(f"  {key}: {value},\n")
        output_lines.append("};\n\nexport type URLS = typeof URLS;\n")

        output_path = options["output"]
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.writelines(output_lines)

        self.stdout.write(self.style.SUCCESS(f"Exported {len(filtered_routes)} routes to {output_path}"))
