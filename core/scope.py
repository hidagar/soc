"""Customer scope is request-local. Root/background jobs explicitly have no scope."""
from contextvars import ContextVar
from django.db import models

customer_scope = ContextVar('soc_customer_scope', default=None)
actor_scope = ContextVar('soc_actor_scope', default=None)

class ScopedManager(models.Manager):
    def get_queryset(self):
        q = super().get_queryset()
        ids = customer_scope.get()
        if ids is None:
            return q
        lookup = getattr(self.model, 'customer_lookup', 'client_id')
        return q.filter(**{lookup + '__in': ids})
