"""Readable audit projection. Signed records are never rewritten."""
import json
from django.apps import apps
from django.contrib.auth import get_user_model
from django.urls import reverse

ACTIONS = {
    'staff.invitation_queued':'Invitación de acceso preparada',
    'staff.invitation_sent':'Correo de bienvenida aceptado para envío',
    'staff.invitation_accepted':'Contraseña establecida por el usuario',
    'logs.https_prepared':'Recepción HTTPS preparada para el equipo',
    'logs.https_disabled':'Recepción HTTPS desactivada',
    'logs.https_rotated':'Clave de envío HTTPS renovada',
    'logs.https_verification':'Comprobación de envío HTTPS iniciada',
    'logs.https_credentials_downloaded':'Paquete protegido del reenviador descargado',
    'zenarmor.export_requested':'Configuración Syslog de Zenarmor solicitada',
    'zenarmor.export_configured':'Destino Syslog y Alerts de Zenarmor confirmados',
    'password_login': 'Inicio de sesión con contraseña',
    'mfa.verified': 'Segundo factor verificado', 'mfa.enrolled': 'Autenticador configurado',
    'mfa.reset': 'Autenticador restablecido', 'staff.access': 'Permisos de usuario actualizados',
    'incident.automatic': 'Incidencia creada automáticamente', 'incident.claimed': 'Incidencia asumida por un operador',
    'incident.note': 'Nota añadida a la incidencia', 'incident.action_saved': 'Acción de seguimiento guardada',
    'intelligence.incident': 'Seguimiento de una detección abierto',
    'firewall.backup_saved': 'Configuración del firewall respaldada',
    'firewall.backup_review': 'Copia del firewall revisada', 'backup.verified': 'Copia del SOC verificada',
    'backup.queued': 'Copia del SOC solicitada', 'recovery.settings': 'Configuración de recuperación guardada',
    'asset.identity': 'Identidad del equipo revisada', 'health.recheck': 'Comprobación del equipo solicitada',
    'health.settings': 'Seguimiento del equipo actualizado', 'network.recheck_requested': 'Consulta de redes solicitada',
    'network.requirements': 'Requisitos de una red guardados', 'protection.recheck': 'Consulta de motores solicitada',
    'protection.requirements': 'Requisitos de protección guardados', 'protection.incident': 'Seguimiento de protección abierto',
    'protection.test_started': 'Prueba de detección preparada', 'protection.test_received': 'Detección de prueba recibida',
    'exposure.recheck': 'Revisión de exposición solicitada', 'exposure.interfaces': 'Interfaces externas declaradas',
    'exposure.incident': 'Seguimiento de exposición abierto', 'exposure.review': 'Hallazgo de exposición revisado',
    'runbook.prepared': 'Guía de investigación preparada', 'runbook.updated': 'Paso de investigación actualizado',
    'customer.task_saved': 'Tarea para el cliente guardada', 'customer.task_response': 'Respuesta del cliente recibida',
    'customer.publication': 'Comunicación al cliente guardada', 'urgent.acknowledged': 'Atención del aviso urgente registrada',
    'mail.webhook_settings': 'Seguimiento de entrega de correo configurado',
    'change.draft': 'Plan de cambio preparado', 'change.staged': 'Borradores de reglas preparados',
    'change.rollback': 'Cambio revertido', 'change.awaiting_confirmation': 'Cambio pendiente de confirmación',
    'change.applied': 'Cambio confirmado', 'change.stage.approved': 'Preparación de borradores aprobada',
    'change.apply.approved': 'Aplicación del cambio aprobada', 'change.rollback.approved': 'Reversión aprobada',
    'change.confirm.approved': 'Confirmación del cambio solicitada', 'vpn.prepared': 'Configuración VPN preparada',
    'vpn.enable': 'Activación VPN solicitada', 'vpn.disable': 'Desactivación VPN solicitada',
    'vpn.config.download': 'Configuración VPN descargada',
}
ROUTES = {
    'mfa_challenge': 'Verificar segundo factor', 'mfa_setup': 'Configurar autenticador', 'mfa_reset': 'Restablecer autenticador',
    'client_new': 'Añadir cliente', 'client_edit': 'Editar cliente', 'site_new': 'Añadir sede', 'site_edit': 'Editar sede',
    'site_delete': 'Eliminar sede', 'device_new': 'Añadir equipo', 'device_edit': 'Editar equipo',
    'device_onboarding': 'Completar el asistente de conexión', 'onboarding_add_device': 'Añadir equipo a la sede',
    'incident_new': 'Añadir incidencia', 'incident_edit': 'Editar incidencia', 'incident_note': 'Añadir nota',
    'staff_edit': 'Editar permisos de usuario', 'staff': 'Gestionar usuarios', 'mail_settings': 'Configurar correo',
    'opnsense_api': 'Configurar conexión OPNsense', 'unifi_cloud': 'Configurar conexión UniFi',
    'ssh_connection': 'Configurar conexión SSH', 'export_destination': 'Configurar destino de logs',
    'network_requirements': 'Definir requisitos de una red', 'device_coverage': 'Consultar redes del equipo',
    'validations': 'Preparar prueba de detección', 'protection_device': 'Gestionar requisitos de protección',
    'customer_task_edit': 'Editar tarea del cliente', 'customer_task_new': 'Crear tarea del cliente',
    'customer_task_reply': 'Responder a una tarea', 'runbook': 'Actualizar guía de investigación',
    'configuration_archives': 'Revisar copias del firewall', 'delivery_settings': 'Configurar entrega de correo',
    'acknowledge_alert': 'Registrar atención de aviso', 'action_edit': 'Editar acción de seguimiento',
    'action_new': 'Crear acción de seguimiento', 'claim_incident': 'Asumir una incidencia',
    'health_device': 'Gestionar seguimiento del equipo', 'asset_edit': 'Revisar identidad del equipo',
    'changes': 'Preparar plan de cambio', 'change_detail': 'Gestionar un cambio', 'vpn_sites': 'Gestionar VPN',
    'recovery': 'Gestionar recuperación', 'customer_publish': 'Publicar comunicación al cliente',
    'verify_public_reports': 'Comprobar enlace público de informes', 'manage_report_link': 'Gestionar enlace del informe',
    'exposure_recheck': 'Solicitar revisión de exposición', 'exposure_interfaces': 'Declarar interfaces externas',
    'exposure_detail': 'Revisar hallazgo de exposición',
}
FIELDS = {
    'transport':'Método de copia externa','vm_platform':'Plataforma de copias de VM',
    'vm_storage':'Repositorio de copias de VM','vm_offhost':'Almacenamiento externo declarado',
    'vm_encrypted':'Cifrado declarado','vm_last_backup_at':'Última copia de VM declarada',
    'vm_last_restore_at':'Último ensayo de VM declarado','vm_restore_isolated':'Red aislada declarada',
    'vm_restore_reference':'Referencia del ensayo de VM',
    'name': 'Nombre', 'code': 'Identificador', 'client': 'Cliente', 'site': 'Sede', 'device': 'Equipo',
    'active': 'Activo', 'scope': 'Ámbito del servicio', 'role': 'Perfil', 'clients': 'Clientes asignados',
    'all_clients': 'Acceso a todos los clientes', 'require_ips': 'IPS requerido', 'require_zenarmor': 'Zenarmor requerido',
    'require_clamav': 'ClamAV requerido', 'notes': 'Notas', 'review_note': 'Justificación de revisión',
    'review_until': 'Fecha de revisión', 'owner': 'Responsable', 'owner_contact': 'Contacto del responsable',
    'due_at': 'Fecha límite', 'status': 'Estado', 'resolution': 'Evidencia de resolución',
    'title': 'Título', 'description': 'Descripción', 'severity': 'Gravedad', 'recommendation': 'Recomendación',
    'function': 'Función del equipo', 'vlan': 'VLAN', 'critical': 'Equipo crítico', 'confirm_identity': 'Identidad confirmada',
    'maintenance_until': 'Fin del mantenimiento', 'expected_silence_minutes': 'Umbral de silencio',
    'external_interfaces': 'Interfaces externas', 'public_key': 'Clave pública de firma', 'enabled': 'Activado',
    'ack_minutes': 'Plazo de atención de avisos', 'visible': 'Publicación en el portal', 'instructions': 'Instrucciones',
    'response': 'Respuesta del cliente', 'action': 'Acción vinculada', 'summary': 'Resumen', 'next_steps': 'Próximos pasos',
    'from_email': 'Remitente', 'reply_to_email': 'Dirección de respuesta', 'bcc_email': 'Copia oculta',
    'reports_email': 'Correo de informes', 'report_email': 'Correo de informes', 'report_enabled': 'Envío de informes',
    'host': 'Servidor', 'port': 'Puerto', 'username': 'Usuario', 'directory': 'Directorio de destino',
    'retention_days': 'Días de conservación', 'sftp_host': 'Servidor SFTP', 'sftp_port': 'Puerto SFTP',
    'sftp_user': 'Usuario SFTP', 'sftp_path': 'Ruta SFTP', 'encrypted_password': 'Credencial de acceso',
}
STATUSES = {'open':'Pendiente', 'investigating':'En investigación', 'resolved':'Resuelto', 'pending':'Pendiente',
    'done':'Completado', 'cancelled':'Cancelado', 'in_progress':'En curso', 'awaiting_client':'Esperando al cliente',
    'submitted':'Respuesta recibida; pendiente de revisión', 'accepted':'Validado', 'rework':'Requiere más información',
    'blocked':'Bloqueada', 'allowed':'Permitida', 'unknown':'Sin determinar', 'published':'Publicado', 'draft':'Borrador'}
ROLES = {'reader':'Consulta', 'operator':'Operador', 'manager':'Administrador SOC', 'customer':'Cliente'}

# Values-only queries: no connector credentials or MFA secrets are fetched for object names.
OBJECTS = {
    'Incident': ('Incidencia', 'title', 'incident_detail', 'pk'),
    'Client': ('Cliente', 'name', 'client_detail', 'pk'), 'Site': ('Sede', 'name', 'site_detail', 'pk'),
    'Device': ('Equipo', 'name', 'device_detail', 'pk'),
    'ConfigurationArchive': ('Copia de configuración', 'device__name', 'configuration_archives', 'device_id'),
    'MfaProfile': ('Autenticador', 'user__username', None, None),
    'StaffAccess': ('Permisos de usuario', 'user__username', None, None),
    'ProtectionPolicy': ('Protección', 'device__name', 'protection_device', 'device_id'),
    'DeviceHealth': ('Seguimiento del equipo', 'device__name', 'health_device', 'device_id'),
    'NetworkCoverage': ('Red', 'name', 'device_coverage', 'device_id'),
    'ExposureCheck': ('Revisión de exposición', 'device__name', 'device_detail', 'device_id'),
    'ExposureFinding': ('Hallazgo de exposición', 'title', 'exposure_detail', 'pk'),
    'ChangePlan': ('Plan de cambio', 'title', 'change_detail', 'pk'),
    'IncidentAction': ('Acción de seguimiento', 'title', 'incident_detail', 'incident_id'),
    'RunbookStep': ('Paso de investigación', 'title', 'incident_detail', 'incident_id'),
    'CustomerTask': ('Tarea del cliente', 'title', 'incident_detail', 'incident_id'),
    'CustomerPublication': ('Comunicación al cliente', 'title', 'client_detail', 'client_id'),
    'ProtectionValidation': ('Prueba de detección', 'device__name', 'validations', 'device_id'),
    'UrgentAlert': ('Aviso urgente', 'signature', None, None),
    'Asset': ('Equipo del inventario', 'ip', 'asset_edit', 'pk'),
    'VpnPeer': ('VPN de la sede', 'site__name', None, None),
    'BackupRun': ('Copia del SOC', None, None, None),
    'RecoverySettings': ('Configuración de recuperación', None, None, None),
    'DeliverySettings': ('Entrega de correo', None, None, None),
    'MailSettings': ('Correo del SOC', None, None, None),
}


def object_labels(events):
    result={}
    for kind, definition in OBJECTS.items():
        ids={int(e.object_id) for e in events if e.object_type==kind and e.object_id.isdigit()
             and len(e.object_id)<=19 and 0<int(e.object_id)<2**63}
        if not ids:continue
        label, name, route, target=definition
        fields=list(dict.fromkeys(['pk']+([name] if name else [])+([target] if target else [])))
        for item in apps.get_model('core',kind).objects.filter(pk__in=ids).values(*fields):
            title=label+' #'+str(item['pk'])+(' · '+str(item[name]) if name and item.get(name) else '')
            url=reverse(route,args=[item[target]]) if route and item.get(target) else ''
            result[(kind,str(item['pk']))]=(title,url)
    # The staff-access operation records the user model rather than StaffAccess.
    user_model=get_user_model()
    ids={int(e.object_id) for e in events if e.object_type==user_model.__name__ and e.object_id.isdigit()
         and len(e.object_id)<=19 and 0<int(e.object_id)<2**63}
    for item in user_model.objects.filter(pk__in=ids).values('pk','username'):
        result[(user_model.__name__,str(item['pk']))]=('Usuario · '+item['username'],'')
    return result


def detail_lines(event):
    data=event.details if isinstance(event.details,dict) else {}
    lines=[]
    status=data.get('status')
    if isinstance(status,int) and not isinstance(status,bool):
        labels={200:'Página mostrada',201:'Recurso creado',202:'Solicitud aceptada para procesamiento',
            204:'Solicitud completada sin contenido',301:'Redirección a otra página',302:'Redirección a otra página',303:'Redirección a otra página'}
        lines.append(labels.get(status,'Respuesta del servidor')+' (HTTP '+str(status)+').')
    elif isinstance(status,str):
        lines.append('Estado registrado: '+STATUSES.get(status,'Consultar datos técnicos')+'.')
    fields=data.get('fields')
    if isinstance(fields,list) and fields:
        names=list(dict.fromkeys(FIELDS.get(f,'Otro campo') for f in fields[:30] if isinstance(f,str)))
        if names:lines.append('Campos modificados: '+', '.join(names)+'.')
    count=data.get('count')
    if isinstance(count,int) and not isinstance(count,bool) and count>=0:
        if event.action=='incident.automatic':
            lines.append(str(count)+(' detección relacionada' if count==1 else ' detecciones relacionadas')+' al crear el caso.')
        elif event.action=='firewall.backup_saved':
            lines.append(str(count)+(' sección con cambios registrada' if count==1 else ' secciones con cambios registradas')+'.')
        elif event.action=='change.staged':
            lines.append(str(count)+(' borrador de regla preparado' if count==1 else ' borradores de reglas preparados')+'.')
        else:lines.append('Cantidad registrada: '+str(count)+'.')
    if isinstance(data.get('role'),str):lines.append('Perfil asignado: '+ROLES.get(data['role'],'Consultar datos técnicos')+'.')
    if isinstance(data.get('clients'),list):lines.append('Clientes asignados registrados: '+str(len(data['clients']))+'.')
    if data.get('sha256'):lines.append('Huella de integridad registrada; disponible en los datos técnicos.')
    defaults={'password_login':'Se ha iniciado sesión con contraseña.', 'mfa.verified':'Segundo factor comprobado correctamente.',
        'mfa.enrolled':'El usuario ha configurado su autenticador.', 'mfa.reset':'Se ha restablecido el autenticador del usuario.',
        'firewall.backup_saved':'Configuración cifrada y comprobada por descifrado y huella de integridad.',
        'backup.verified':'Se ha completado la verificación de la copia del SOC.',
        'urgent.acknowledged':'El SOC ha registrado que ha visto el aviso; el caso mantiene su seguimiento.',
        'protection.test_started':'Ventana de una hora preparada para correlacionar una detección real.',
        'runbook.prepared':'Se ha preparado la guía de investigación de la incidencia.'}
    if event.action in defaults:lines.insert(0,defaults[event.action])
    return lines or ['Sin detalle adicional registrado.']


def present(events):
    events=list(events);objects=object_labels(events);rows=[]
    for event in events:
        action=ACTIONS.get(event.action)
        if not action and event.action.startswith('portal.'):
            action='Solicitud: '+ROUTES.get(event.action[7:],'operación del panel')
        label,url=objects.get((event.object_type,event.object_id),('', ''))
        if not label:
            kind=OBJECTS.get(event.object_type,('Elemento',))[0]
            label=(kind+' #'+event.object_id+' · ficha no disponible') if event.object_type else 'Sesión del usuario'
        rows.append({'event':event,'action':action or 'Operación registrada',
            'actor':'Proceso automático' if event.actor_name=='system' else event.actor_name,
            'object':label,'url':url,'details':detail_lines(event),
            'technical':json.dumps(event.details,ensure_ascii=False,indent=2,sort_keys=True)})
    return rows
