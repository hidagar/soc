def connection_permissions(request):
    user = request.user
    global_access = bool(user.is_authenticated and (user.is_superuser or
        getattr(getattr(user,'soc_access',None),'all_clients',False)))
    return {"can_manage_connections": user.is_authenticated and user.has_perm("core.manage_connections"),
            "soc_global_access":global_access}
