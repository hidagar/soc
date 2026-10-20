from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    def ready(self):
        from django.db.models.signals import post_migrate
        from .roles import synchronize_roles
        post_migrate.connect(synchronize_roles,sender=self,dispatch_uid='soc-role-permissions')
        from django.contrib.auth.signals import user_logged_in
        def password_login(sender,request,user,**kwargs):
            if request is not None and request.method=='POST' and request.path in ('/login/','/admin/login/'):
                request.soc_password_login_user=user
        user_logged_in.connect(password_login,dispatch_uid='soc-password-login-result',weak=False)
        from django.db.models.signals import pre_save,pre_delete,post_save,post_delete
        from .models import Client,Device,Site,ExportConfiguration,SecureLogChannel
        from .source_ownership import synchronize,capture
        for model in (Client,Device,Site,ExportConfiguration,SecureLogChannel):
            pre_save.connect(capture,sender=model,dispatch_uid='source-owner-before-save-'+model.__name__)
            pre_delete.connect(capture,sender=model,dispatch_uid='source-owner-before-delete-'+model.__name__)
            post_save.connect(synchronize,sender=model,dispatch_uid='source-owner-save-'+model.__name__)
            post_delete.connect(synchronize,sender=model,dispatch_uid='source-owner-delete-'+model.__name__)
