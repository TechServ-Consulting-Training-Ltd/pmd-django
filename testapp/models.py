from django.db import models
from django.utils.timezone import now


class TestModel(models.Model):
    status = models.CharField(max_length=100)
    tags = models.JSONField(default=list)
    created_at = models.DateTimeField(default=now)
    metadata_not_for_download = models.TextField()

    class Meta:
        db_table = "test_model"
        app_label = 'testapp'

class TestRelatedModel(models.Model):
    name = models.TextField()
    related = models.ForeignKey(TestModel, on_delete=models.CASCADE)

    class Meta:
        db_table = "test_related_model"
        app_label = 'testapp'

class UniqueModel(models.Model):
    code = models.TextField(unique=True)
    related = models.ForeignKey("testapp.TestRelatedModel", on_delete=models.CASCADE, null=True)

    class Meta:
        db_table = "test_unique_model"
        app_label = 'testapp'
