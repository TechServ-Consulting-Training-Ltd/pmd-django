from typing import TypeAlias, Tuple, Optional

from django.views import View
from django.db.models import QuerySet
from django.core.exceptions import ImproperlyConfigured
from pmd_django.generic_table.generic_table import view
from pmd_django.query_helpers import build_filtered_queryset

FrontendFieldOptions: TypeAlias = dict
FrontendFieldType: TypeAlias = str
FrontendHeaderDisplayName: TypeAlias = str
BackendAttributeName: TypeAlias = str
FrontendHeaderSettings: TypeAlias = Tuple[FrontendHeaderDisplayName, Tuple[FrontendFieldType, FrontendFieldOptions]]
StageDisplayValue: TypeAlias = str
StageDBValue: TypeAlias = str


class GenericTableView(View):
    queryset = None
    model = None
    stage_field: str = ""
    counted_stages: dict[StageDisplayValue, StageDBValue] = {}
    should_add_all: bool = True
    table_headers: dict[BackendAttributeName, Optional[FrontendHeaderSettings]] = {}

    # https://github.com/django/django/blob/5a1cae3a5675c5733daf5949759476d65aa0e636/django/views/generic/list.py#L22C5-L48C1
    def get_queryset(self):
        if self.queryset is not None:
            queryset = self.queryset
            if isinstance(queryset, QuerySet):
                queryset = queryset.all()
        elif self.model is not None:
            queryset = self.model._default_manager.all()
        else:
            raise ImproperlyConfigured(
                "%(cls)s is missing a QuerySet. Define "
                "%(cls)s.model, %(cls)s.queryset, or override "
                "%(cls)s.get_queryset()." % {"cls": self.__class__.__name__}
            )
        return queryset

    def get(self, request, *args, **kwargs):
        return view(
            qs=self.get_queryset(),
            request=request,
            **self.generic_table_view_kwargs
        )

    @property
    def generic_table_view_kwargs(self):
        return {
            "field": self.stage_field,
            "values_list": list(self.table_headers.keys()),
            "counted_values": list(self.counted_stages.values()),
            "data_key": "data",
            "final_json_hook": self.final_json_hook,
        }

    def final_json_hook(self, data: dict) -> dict:
        counted_stages = self.counted_stages
        if self.should_add_all:
            counted_stages = {"All": "ALL"} | self.counted_stages
        data["displayStageAttr"] = self.stage_field
        data["displayStages"] = counted_stages
        data["displayHeaders"] = {k: v[0] for k, v in self.table_headers.items() if v}
        data["filterFieldTypes"] = {
            k: v[1][0] for k, v in self.table_headers.items() if v
        }
        return data

    @staticmethod
    def bulk(request, view_class, query, update_fn):
        self = view_class()

        filtered_qs = build_filtered_queryset(
            self.get_queryset(),
            query,
            field=self.stage_field,
            counted_values=list(self.counted_stages.values()),
            extra_filter_from_request=self.generic_table_view_kwargs.get("extra_filter_from_request"),
        )

        return update_fn(filtered_qs)
