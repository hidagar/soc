"""Email login, with two explicitly retained pre-existing operator accounts."""
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.admin.forms import AdminAuthenticationForm
from django.db.models.functions import Lower, Trim

LEGACY_USERNAMES = frozenset(('kico', 'ibred'))


class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None
        identity=str(username).strip().lower()
        User=get_user_model()
        matches=list(User._default_manager.annotate(login_email=Lower(Trim('email')))
                     .filter(login_email=identity).exclude(login_email='')[:2])
        if not matches and identity in LEGACY_USERNAMES:
            matches=list(User._default_manager.filter(username=identity,email='')[:2])
        if len(matches)!=1:
            # Match Django's missing-user password hashing cost; never guess between duplicates.
            User().set_password(password)
            return None
        user=matches[0]
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None


class EmailAuthenticationForm(AuthenticationForm):
    # CharField deliberately retains the two legacy logins, alongside email input.
    username=forms.CharField(label='Correo electrónico',max_length=254,
        widget=forms.TextInput(attrs={'autofocus':True,'autocomplete':'username','inputmode':'email'}))
    error_messages={**AuthenticationForm.error_messages,
        'invalid_login':'Correo o contraseña incorrectos.'}


class EmailAdminAuthenticationForm(AdminAuthenticationForm):
    username=EmailAuthenticationForm.base_fields['username']
    error_messages={**AdminAuthenticationForm.error_messages,
        'invalid_login':'Correo o contraseña incorrectos, o sin permiso de administración.'}
