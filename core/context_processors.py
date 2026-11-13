from .navigation import build_navigation, intel_tabs


def connection_permissions(request):
    user = request.user
    global_access = bool(user.is_authenticated and (user.is_superuser or
        getattr(getattr(user,'soc_access',None),'all_clients',False)))
    return {"can_manage_connections": user.is_authenticated and user.has_perm("core.manage_connections"),
            "soc_global_access":global_access,
            "nav_search": user.is_authenticated and getattr(getattr(user, 'soc_access', None), 'role', '') != 'customer',
            "intel_tabs": intel_tabs(request) if user.is_authenticated else [],
            "nav_groups": build_navigation(request, global_access) if user.is_authenticated else []}
