from datetime import timedelta
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST
from .models import Device
from .device_inventory import refresh, InventoryError


@login_required
@require_POST
def refresh_inventory(request, pk):
    if not request.user.has_perm('core.manage_connections') or not request.user.has_perm('core.change_device'):
        return HttpResponseForbidden('Tu cuenta no tiene permiso para actualizar el inventario.')
    device = get_object_or_404(Device.objects.select_related('site'), pk=pk)
    if device.inventory_checked_at and timezone.now() - device.inventory_checked_at < timedelta(minutes=1):
        messages.info(request, 'Espera un minuto entre consultas de inventario.')
    else:
        try:
            result = refresh(device)
            if result.inventory_metadata.get('status') in ('ok', 'partial'):
                messages.success(request, 'Datos técnicos consultados. Los campos no facilitados se conservan o quedan pendientes.')
            else:
                messages.warning(request, result.inventory_metadata.get('message', 'Inventario pendiente.'))
        except InventoryError as exc:
            messages.warning(request, str(exc))
    return redirect('device_detail', pk=pk)
