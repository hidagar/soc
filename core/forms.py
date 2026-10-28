from django import forms
from django.core.exceptions import FieldDoesNotExist
from django.forms import formset_factory
from django.utils.text import slugify
from django.utils import timezone

from .models import Client, Device, Incident, MailSettings, Site
from .opnsense_api import OpnsenseApiError, validate_api_url, validate_ca_certificate


class ScopedModelForm(forms.ModelForm):
    """ModelForm cuyas listas de opciones respetan el ámbito de cliente de la petición actual.

    Django crea el queryset de cada campo relacionado al importar el formulario y
    ScopedManager filtra en ese momento (invariante 1): sin rehacerlo, la lista conservaría
    el ámbito de la primera petición del proceso, o ninguno, y un usuario limitado podría
    elegir y escribir sedes, equipos o clientes ajenos. Los campos declarados en la clase
    y los que cada formulario restringe después en su __init__ se respetan.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            if not isinstance(field, forms.ModelChoiceField) or name in self.declared_fields:
                continue
            try:
                model_field = self._meta.model._meta.get_field(name)
            except FieldDoesNotExist:
                continue
            if model_field.remote_field is not None:
                field.queryset = model_field.remote_field.model._default_manager.complex_filter(
                    model_field.get_limit_choices_to() or {})


class StyledModelForm(ScopedModelForm):
    sections = None  # [{'title', 'fields', 'collapsed', 'hint'}]: grupos que pinta object_form.html

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "input")

    @property
    def section_list(self):
        """Secciones con sus campos ligados. Un campo no listado va a la primera; una plegada se abre si tiene errores."""
        if not self.sections:
            return None
        listed = {name for section in self.sections for name in section['fields']}
        result = []
        for index, section in enumerate(self.sections):
            names = [name for name in section['fields'] if name in self.fields]
            if index == 0:
                names += [name for name in self.fields if name not in listed]
            bound = [self[name] for name in names]
            result.append({**section, 'bound': bound, 'open': any(field.errors for field in bound)})
        return result


class ClientForm(StyledModelForm):
    sections = [
        {'title': 'Datos del cliente', 'fields': ['name', 'code', 'contact_email', 'active', 'notes']},
        {'title': 'Informes y portal del cliente', 'fields': ['report_email', 'weekly_reports_enabled',
                                                             'customer_portal_detail_enabled', 'customer_live_map_enabled']},
        {'title': 'Avisos urgentes', 'fields': ['urgent_alerts_enabled', 'urgent_email', 'urgent_availability_enabled']},
    ]

    class Meta:
        model = Client
        fields = ["name", "code", "contact_email", "report_email", "weekly_reports_enabled", "customer_live_map_enabled", "customer_portal_detail_enabled", "urgent_email", "urgent_alerts_enabled", "urgent_availability_enabled", "active", "notes"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["report_email"].help_text = "Destinatario del informe de seguridad. Puede ser distinto del contacto general."
        self.fields["weekly_reports_enabled"].help_text = "Se enviará cada lunes si hay eventos recibidos y el correo del servidor está configurado."
        self.fields["urgent_email"].help_text = "Opcional: si queda vacío, se usará el correo de informes semanales."
        self.fields["urgent_alerts_enabled"].help_text = "Envía avisos de seguridad urgentes en pocos minutos. Los intentos bloqueados habituales quedan en el informe semanal."
        self.fields["urgent_availability_enabled"].help_text = "También avisa de eventos «Internet Down». Requiere activar los avisos urgentes."

    def clean(self):
        values = super().clean()
        if values.get("weekly_reports_enabled") and not values.get("report_email"):
            self.add_error("report_email", "Indica el correo que recibirá el informe antes de activar el envío.")
        if values.get("urgent_alerts_enabled") and not (values.get("urgent_email") or values.get("report_email")):
            self.add_error("urgent_email", "Indica el correo para avisos urgentes o el de informes semanales.")
        if values.get("urgent_availability_enabled") and not values.get("urgent_alerts_enabled"):
            self.add_error("urgent_availability_enabled", "Activa primero los avisos urgentes.")
        return values


class MailSettingsForm(StyledModelForm):
    api_key = forms.CharField(
        label="Clave API de SendGrid", required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Clave con permiso Mail Send. Déjala vacía para conservar la guardada; no se vuelve a mostrar.",
    )
    test_email = forms.EmailField(label="Enviar prueba a", required=False,
                                  help_text="Dirección interna donde comprobarás la llegada del correo de prueba.")

    class Meta:
        model = MailSettings
        fields = ["region", "from_email", "reply_to_email", "report_copy_email", "public_reports_url"]

    def clean(self):
        values = super().clean()
        if not values.get("api_key") and not self.instance.encrypted_api_key:
            self.add_error("api_key", "Indica la clave API para configurar SendGrid.")
        if values.get("public_reports_url"):
            from .report_sharing import validate_public_url
            try:
                values["public_reports_url"] = validate_public_url(values["public_reports_url"])
            except ValueError as exc:
                self.add_error("public_reports_url", str(exc))
        return values


class SiteForm(StyledModelForm):
    class Meta:
        model = Site
        fields = ["client", "name", "code"]

    def __init__(self, *args, selected_client=None, **kwargs):
        super().__init__(*args, **kwargs)
        if selected_client is not None:
            self.initial['client'] = selected_client.pk
            self.fields['client'].queryset = Client.objects.filter(pk=selected_client.pk)
            self.fields['client'].widget = forms.HiddenInput()
            # Bind to the client from the page context, including validation retries.
            # A posted client value cannot move this new site to another customer.
            self.fields['client'].disabled = True
        self.fields["code"].required = False
        self.fields["code"].help_text = "Opcional. Si queda vacío, se genera a partir del nombre."

    def clean(self):
        values = super().clean()
        client = values.get("client")
        name = values.get("name")
        if client and name and not values.get("code"):
            base = (slugify(name, allow_unicode=False) or "sede")[:50]
            code = base
            suffix = 2
            while Site.objects.filter(client=client, code=code).exclude(pk=self.instance.pk).exists():
                ending = f"-{suffix}"
                code = base[:50 - len(ending)] + ending
                suffix += 1
            values["code"] = code
        return values


class SiteEditForm(StyledModelForm):
    class Meta:
        model = Site
        fields = ["client", "name", "code", "address", "active", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 3})}


class DeviceForm(StyledModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .device_inventory import FIELDS, provider, facts
        self.automatic_inventory = bool(self.instance.pk and provider(self.instance)[1])
        # Los datos de conexión los fija el asistente; aquí quedan aparte, como ajuste avanzado.
        connection = ('management_method', 'log_method', 'management_address', 'ssh_username', 'wazuh_identifier')
        self.display_fields = [self[name] for name in self.fields if name not in FIELDS and name not in connection]
        self.connection_fields = [self[name] for name in connection]
        self.manual_inventory_fields = []
        self.inventory_facts = facts(self.instance)
        for name in FIELDS:
            self.fields[name].required = False
            self.fields[name].disabled = self.automatic_inventory
            if not self.automatic_inventory: self.manual_inventory_fields.append(self[name])

    def save(self, commit=True):
        device = super().save(commit=False)
        if {'mac_address', 'vendor', 'management_method', 'management_address'} & set(self.changed_data):
            device.inventory_checked_at = None
        if commit:
            device.save()
            self.save_m2m()
        return device

    class Meta:
        model = Device
        fields = ["site", "name", "vendor", "model", "mac_address", "software_version", "management_method", "log_method", "zenarmor_enabled", "zenarmor_edition", "zenarmor_version", "management_address", "ssh_username", "serial_number", "wazuh_identifier", "active", "notes"]


class SiteDeviceForm(StyledModelForm):
    api_key = forms.CharField(label="Clave API", max_length=512, required=False, widget=forms.PasswordInput(render_value=False))
    api_secret = forms.CharField(label="Secreto API", max_length=512, required=False, widget=forms.PasswordInput(render_value=False))
    api_url = forms.URLField(label="Dirección HTTPS de OPNsense", max_length=255, required=False)
    ca_certificate = forms.CharField(label="Certificado CA (si es privado)", required=False, widget=forms.Textarea(attrs={"rows": 3}))

    class Meta:
        model = Device
        fields = ["name", "vendor", "management_method", "management_address", "ssh_username"]

    def __init__(self, *args, **kwargs):
        self.can_manage_connections = kwargs.pop("can_manage_connections", False)
        super().__init__(*args, **kwargs)
        self.fields["management_method"].required = False
        self.initial["management_method"] = ""
        for field in self.fields.values():
            field.widget.attrs.setdefault("class", "input")

    def clean(self):
        values = super().clean()
        if values.get("name"):
            method = values.get("management_method") or Device.ManagementMethod.NONE
            vendor = values.get("vendor")
            values["management_method"] = method
            if method == Device.ManagementMethod.API:
                if not self.can_manage_connections:
                    self.add_error("management_method", "Tu cuenta necesita permiso para gestionar conexiones API.")
                elif vendor == Device.Vendor.UNIFI and not values.get("api_key"):
                    self.add_error("api_key", "Indica la clave API de UniFi Cloud.")
                elif vendor == Device.Vendor.OPNSENSE:
                    for field in ("api_url", "api_key", "api_secret"):
                        if not values.get(field):
                            self.add_error(field, "Este dato es necesario para conectar OPNsense.")
                    if values.get("api_url"):
                        try:
                            values["api_url"] = validate_api_url(values["api_url"])
                        except OpnsenseApiError as exc:
                            self.add_error("api_url", str(exc))
                    try:
                        values["ca_certificate"] = validate_ca_certificate(values.get("ca_certificate", ""))
                    except OpnsenseApiError as exc:
                        self.add_error("ca_certificate", str(exc))
            elif method == Device.ManagementMethod.SSH:
                for field in ("management_address", "ssh_username"):
                    if not values.get(field):
                        self.add_error(field, "Indica este dato para el acceso SSH.")
        return values


SiteDeviceFormSet = formset_factory(SiteDeviceForm, extra=1, max_num=20, validate_max=True)


class IncidentForm(StyledModelForm):
    sections = [
        {'title': 'Qué ha pasado', 'fields': ['client', 'site', 'device', 'title', 'description']},
        {'title': 'Clasificación', 'fields': ['severity', 'status', 'owner', 'observed_at']},
        {'title': 'Cierre y referencias', 'fields': ['resolved_at', 'wazuh_alert_id', 'actions'], 'collapsed': True,
         'hint': 'La fecha de resolución se rellena sola al marcar «Resuelta». Para el trabajo pendiente usa el plan de acciones de la ficha.'},
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['actions'].label = 'Notas de acciones (texto libre)'

    def clean(self):
        values=super().clean()
        if values.get('status')=='resolved' and not values.get('resolved_at'):
            values['resolved_at']=timezone.now()
        elif values.get('status') in ('open','investigating'):
            values['resolved_at']=None
        if self.instance.pk:
            from .models import IncidentAction
            tasks=IncidentAction.objects.filter(incident_id=self.instance.pk)
            resolving=values.get('status')=='resolved'
            if resolving and tasks.exclude(status__in=['done','cancelled']).exists():
                self.add_error('status','Completa o cancela las acciones pendientes antes de resolver la incidencia.')
            if resolving and self.instance.runbook_steps.filter(done=False).exists():
                self.add_error('status','Completa la guía de comprobaciones con evidencia antes de resolver el caso.')
            if resolving and self.instance.customer_tasks.exclude(status__in=('accepted','cancelled')).exists():
                self.add_error('status','Revisa las tareas del cliente antes de resolver el caso.')
            if self.instance.customer_tasks.exists() and values.get('client') and values['client'].pk!=self.instance.client_id:
                self.add_error('client','Una incidencia con tareas del cliente debe conservar su empresa.')
            if tasks.exists() and values.get('client') and values['client'].pk!=self.instance.client_id:
                self.add_error('client','Una incidencia con acciones de seguimiento debe conservar su cliente.')
        return values
    class Meta:
        model = Incident
        fields = ["client", "site", "device", "title", "description", "severity", "status", "owner", "observed_at", "resolved_at", "wazuh_alert_id", "actions"]
        widgets = {
            "observed_at": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
            "resolved_at": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["observed_at"].input_formats = ["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"]
        self.fields["resolved_at"].input_formats = ["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"]
        client_id = self.data.get("client") if self.is_bound else self.initial.get("client") or self.instance.client_id
        site_id = self.data.get("site") if self.is_bound else self.initial.get("site") or self.instance.site_id
        self.fields["site"].queryset = Site.objects.filter(client_id=client_id) if str(client_id).isdigit() else Site.objects.none()
        self.fields["device"].queryset = Device.objects.filter(site_id=site_id) if str(site_id).isdigit() else Device.objects.none()
        from django.contrib.auth import get_user_model
        from django.db.models import Q
        self.fields['owner'].queryset=get_user_model().objects.filter(is_active=True).filter(
            Q(is_superuser=True)|Q(soc_access__all_clients=True)|Q(soc_access__clients__pk=client_id)).exclude(
            soc_access__role='customer').distinct() if str(client_id).isdigit() else get_user_model().objects.none()
