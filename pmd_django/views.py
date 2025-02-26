from django.views import View
from django.db.models import QuerySet
from django.core.exceptions import ImproperlyConfigured
from generic_table.generic_table import view

class GenericTableView(View):
    generic_table_view_kwargs = {}
    queryset = None
    model = None

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
