from django.apps import AppConfig
from django.core.signals import setting_changed

class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    def ready(self):
        import core.signals