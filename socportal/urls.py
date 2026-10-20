from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from core.email_auth import EmailAuthenticationForm


urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", auth_views.LoginView.as_view(template_name="login.html", authentication_form=EmailAuthenticationForm), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("core.urls")),
]
