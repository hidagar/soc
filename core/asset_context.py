"""Current configuration context, never proof of historical NAT or infection.

No raw configuration, credentials, names or MACs are persisted. Candidate
targets never replace immutable event-time identity or change an incident.
"""
import hashlib,ipaddress,json,re
from datetime import timedelta
from xml.etree import ElementTree as ET
from django.utils import timezone
from .models import AttributionCatalog,Device

def address(value):
    try:return str(ipaddress.ip_address(value))
    except (ValueError,TypeError):return ''

def port(value):
    try:
        if isinstance(value,bool):return None
        n=int(value)
        return n if 1<=n<=65535 else None
    except (ValueError,TypeError):return None

def flow_projection(source):
    data=source.get('data',{})
    if not isinstance(data,dict):return {}
    from .hillstone_events import flow as hillstone_flow
    parsed=hillstone_flow(data)
    if parsed:
        protocol=parsed['protocol'].upper().split('/')[-1]
        return {'protocol':protocol if protocol in ('TCP','UDP','ICMP','ICMPV6') else '',
            'source_port':port(parsed['sport']),'hillstone':{
                'action':parsed['action'],'severity':parsed['severity'],
                'defender':parsed['defender'],'source_interface':parsed['src_interface'],
                'destination_interface':parsed['dst_interface']}}
    protocol=str(data.get('proto') or data.get('protocol') or '').upper()
    if protocol not in ('TCP','UDP','ICMP','ICMPV6'):protocol=''
    return {'protocol':protocol,'source_port':port(data.get('src_port') or data.get('srcport'))}

def digest(data):return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()

def interface_projection(overview):
    rows=overview.get('rows')
    if not isinstance(rows,list) or not 0<len(rows)<=250 or int(overview.get('total',-1))!=len(rows):raise ValueError('Incomplete interfaces')
    out={}
    for row in rows:
        name=row.get('identifier') if isinstance(row,dict) else None
        if name=='':continue # Explicitly unassigned interfaces cannot identify a NAT ingress.
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',name) or name in out:raise ValueError('Ambiguous interface')
        values=[row.get('addr4'),row.get('addr6')]
        for key in ('ipv4','ipv6'):
            value=row.get(key,[]) or []
            if not isinstance(value,list) or len(value)>250:raise ValueError('Invalid addresses')
            values.extend(r.get('ipaddr') for r in value if isinstance(r,dict))
        ips=[]
        for value in values:
            if not value:continue
            try:ip=ipaddress.ip_interface(value).ip
            except (ValueError,TypeError):raise ValueError('Unknown address format')
            if not ip.is_loopback and not ip.is_link_local:ips.append(str(ip))
        out[name]=sorted(set(ips))
    return out

def xml_flag(node,name):
    value=node.find(name)
    if value is None:return False
    text=(value.text or '').strip().lower()
    if text in ('','1','true','yes'):return True
    if text in ('0','false','no'):return False
    raise ValueError('Unknown flag')

def network_specs(value,aliases):
    from .exposure_context import expand
    result=expand(value,aliases,'network')
    if result is None or not result:raise ValueError('Unknown address constraint')
    return result

def port_specs(value,aliases):
    from .exposure_context import expand
    result=expand(value or 'any',aliases,'port')
    if result is None:raise ValueError('Unknown port constraint')
    out=[]
    for token in result:
        if token=='any':return [[1,65535]]
        parts=re.split('[:-]',token)
        low=port(parts[0]);high=port(parts[-1])
        if low is None or high is None or low>high:raise ValueError('Invalid port range')
        out.append([low,high])
    return out

def endpoint(rule,name):
    node=rule.find(name)
    if node is None or xml_flag(node,'not'):raise ValueError('Missing or inverted endpoint')
    if node.find('any') is not None:return 'any'
    # Legacy NAT serializes "any" as an explicitly empty network selector.
    # Missing selectors or unknown endpoint children are never widened.
    if (node.find('network') is not None and not (node.findtext('network') or '').strip()
            and not (node.findtext('address') or '').strip()
            and not set(c.tag for c in node)-{'network','address','port','not'}):return 'any'
    return node.findtext('address') or node.findtext('network') or ''

def configuration_projection(blob,interfaces):
    if len(blob)>16*1024*1024 or b'<!DOCTYPE' in blob.upper() or b'<!ENTITY' in blob.upper():raise ValueError('Unsafe XML')
    root=ET.fromstring(blob)
    if root.tag!='opnsense' or root.find('nat') is None:raise ValueError('Unknown configuration')
    from .exposure_context import alias_catalog
    alias_rows=root.findall('OPNsense/Firewall/Alias/aliases/alias')
    aliases=alias_catalog({'alias':{'aliases':{'alias':{str(i):{c.tag:c.text or '' for c in r} for i,r in enumerate(alias_rows)}}}})
    rules=root.findall('nat/rule')
    if len(rules)>500:raise ValueError('Too many publications')
    out=[];unsupported=0;disabled=0
    for rule in rules:
        try:
            if xml_flag(rule,'disabled'):disabled+=1;continue
            if any(xml_flag(rule,k) for k in ('nordr','interfacenot')) or any(rule.findtext(k) for k in ('tag','tagged','poolopts')):raise ValueError('Unsupported semantics')
            names=(rule.findtext('interface') or '').split(',')
            if not names or any(n not in interfaces for n in names):raise ValueError('Unknown ingress')
            protocol=(rule.findtext('protocol') or 'any').lower()
            if protocol not in ('tcp','udp','tcp/udp','any'):raise ValueError('Unsupported protocol')
            src=network_specs(endpoint(rule,'source'),aliases)
            target=network_specs(rule.findtext('target') or '',aliases)
            if len(target)!=1 or target==['any']:raise ValueError('Ambiguous target')
            host=ipaddress.ip_network(target[0])
            if host.num_addresses!=1 or host.network_address.is_loopback or host.network_address.is_unspecified:raise ValueError('Non-host target')
            dest=endpoint(rule,'destination')
            if dest=='(self)':destinations=sorted(set(ip for n in names for ip in interfaces[n]))
            elif dest in {n+'ip' for n in interfaces}:destinations=interfaces[dest[:-2]]
            else:destinations=network_specs(dest,aliases)
            if not destinations:raise ValueError('Unknown local addresses')
            local=(rule.findtext('local-port') or '').strip()
            target_port=port(local) if local else None
            if local and target_port is None:raise ValueError('Unknown translated port')
            row={'interfaces':names,'protocol':protocol,'source':src,'source_ports':port_specs(rule.findtext('source/port'),aliases),
                 'destinations':destinations,'ports':port_specs(rule.findtext('destination/port'),aliases),
                 'target':str(host.network_address),'target_port':target_port}
            row['id']=rule.get('uuid') or 'configuration-'+digest(row)[:24]
            out.append(row)
        except (ValueError,TypeError):unsupported+=1
    from .zenarmor_bypass import project as bypass_projection
    return {'interfaces':interfaces,'rules':out,'unsupported_rules':unsupported,'disabled_rules':disabled,
        'zenarmor_bypass':bypass_projection(root)}

def collect(device):
    from .configuration_archives import fetch_configuration
    from .provisioning import _api_request
    if device.vendor!='opnsense' or device.management_method!='api':raise ValueError('Unsupported connector')
    api=lambda:_api_request(device.opnsense_api,'/api/interfaces/overview/interfaces_info?rowCount=-1')
    first=configuration_projection(fetch_configuration(device),interface_projection(api()))
    second=configuration_projection(fetch_configuration(device),interface_projection(api()))
    if first!=second:raise ValueError('Concurrent configuration change')
    return second

def refresh(device,now=None):
    now=now or timezone.now()
    row,_=AttributionCatalog.objects.get_or_create(device=device)
    try:
        data=collect(device)
        row.data=data;row.fingerprint=digest(data);row.status='partial' if data['unsupported_rules'] else 'checked'
        row.last_success_at=now
    except Exception:
        row.status='unavailable' # Preserve historical projection without renewing validity.
    row.checked_at=now;row.save()
    return row

def refresh_due(limit=1):
    now=timezone.now();count=0
    for device in Device.objects.filter(active=True,site__active=True,site__client__active=True,vendor='opnsense',management_method='api').exclude(integration='paused').order_by('attribution_catalog__checked_at','pk'):
        row=getattr(device,'attribution_catalog',None)
        if row and row.checked_at and now-row.checked_at<timedelta(minutes=30):continue
        refresh(device,now);count+=1
        if count>=limit:break
    return count

def contains(specs,value):
    ip=address(value)
    if not ip:return False
    return any(s=='any' or ipaddress.ip_address(ip) in ipaddress.ip_network(s,strict=False) for s in specs)

def in_ports(ranges,value):return value is not None and any(low<=value<=high for low,high in ranges)

def review(catalog,src,dst,dstport,flow,now=None):
    now=now or timezone.now()
    if not catalog:return {'status':'unavailable','candidates':[],'firewall_address':False}
    current=bool(catalog.status in ('checked','partial') and catalog.last_success_at and timedelta(0)<=now-catalog.last_success_at<=timedelta(minutes=45))
    result={'status':'current' if current else 'historical','checked_at':catalog.last_success_at,
            'candidates':[],'firewall_address':False,'unsupported_rules':catalog.data.get('unsupported_rules',0)}
    if not current:return result
    result['firewall_address']=dst in {ip for ips in catalog.data.get('interfaces',{}).values() for ip in ips}
    protocol=str(flow.get('protocol','')).lower()
    if protocol not in ('tcp','udp') or not address(src) or not address(dst) or port(dstport) is None:return result
    for row in catalog.data.get('rules',[]):
        if len({ipaddress.ip_address(src).version,ipaddress.ip_address(dst).version,ipaddress.ip_address(row['target']).version})!=1:continue
        if row['protocol'] not in ('any','tcp/udp',protocol):continue
        if not contains(row['source'],src) or not contains(row['destinations'],dst) or not in_ports(row['ports'],port(dstport)):continue
        if row['source_ports']!=[[1,65535]] and not in_ports(row['source_ports'],port(flow.get('source_port'))):continue
        # Configuration match only: effective filter/order/NAT state is not proven.
        translated=row['target_port'] if all(low==high for low,high in row['ports']) else None
        result['candidates'].append({'ip':row['target'],'port':translated,'rule_id':row['id']})
    return result

def describe(result):
    if result['status']=='unavailable':return 'Contexto de interfaces y NAT sin comprobar.'
    if result['status']=='historical':return 'La consulta de interfaces y NAT está antigua o no se pudo renovar. No se atribuye un destino interno.'
    date=timezone.localtime(result['checked_at']).strftime('%d/%m/%Y %H:%M')
    suffix=f' Configuración consultada el {date}; no demuestra la traducción aplicada en la fecha del evento.'
    if result.get('unsupported_rules'):suffix+=f" Hay {result['unsupported_rules']} reglas cuyos criterios requieren revisión manual."
    candidates=result['candidates']
    if candidates:
        targets=sorted({c['ip']+((':'+str(c['port'])) if c['port'] else '') for c in candidates})
        return 'Posibles destinos por publicaciones NAT: '+', '.join(targets[:5])+'. Confirmar regla efectiva, NAT y propietario antes de atribuir el incidente.'+suffix
    if result['firewall_address']:
        return 'El destino registrado coincide con una dirección del firewall. No hay una publicación compatible entre las reglas interpretadas; no se identifica un dispositivo interno.'+suffix
    return 'No se encontró una publicación compatible entre las reglas interpretadas.'+suffix
