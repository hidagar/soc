"""Three-valued evaluation of observed catalogue criteria, never reachability."""
import ipaddress

def project(row):
    raw=row['ipProtocolScope'];ip={'ipVersion':raw['ipVersion']}
    proto=raw.get('protocolFilter')
    if isinstance(proto,dict):
        ip['protocolFilter']={k:proto.get(k) for k in ('type','matchOpposite') if k in proto}
        for k in ('protocol','preset'):
            if isinstance(proto.get(k),dict):ip['protocolFilter'][k]={'name':proto[k].get('name')}
    result={'endpoints':[],'ip':ip,'states':row.get('connectionStateFilter'),'pending':bool(row.get('schedule') is not None or row.get('ipsecFilter') is not None)}
    for field in ('source','destination'):
        endpoint=row[field];traffic=endpoint.get('trafficFilter')
        out={'network':None,'ports':None,'pending':bool(endpoint.get('portFilter') is not None)}
        if traffic is not None:
            kind=traffic.get('type')
            if kind=='NETWORK':out['network']={k:traffic['networkFilter'].get(k) for k in ('networkIds','matchOpposite')}
            elif kind=='IP_ADDRESS':
                from .unifi_policy_details import addresses
                parsed=addresses(traffic.get('ipAddressFilter'))
                if parsed is None:out['pending']=True
                else:out['addresses']=parsed;out['pending'] |= parsed['pending']
            elif kind not in ('PORT',):out['pending']=True
            ports=traffic.get('portFilter')
            if isinstance(ports,dict):
                out['ports']={k:ports.get(k) for k in ('type','matchOpposite')}
                if ports.get('type')=='PORTS':
                    out['ports']['items']=[{'type':item.get('type'),'value':item.get('value') if isinstance(item.get('value'),int) and not isinstance(item.get('value'),bool) else None} for item in ports.get('items',[]) if isinstance(item,dict)]
        result['endpoints'].append(out)
    return result

def conjunction(values):
    return False if False in values else None if None in values else True

def matches(policy,flow):
    shape=policy.get('flow_match')
    if not isinstance(shape,dict):return None
    values=[None if policy.get('criteria_pending') or shape['pending'] else True]
    version=shape['ip']['ipVersion']
    values.append(version=='IPV4_AND_IPV6' or version==flow['ip'])
    proto=shape['ip'].get('protocolFilter')
    if proto:
        if proto.get('type')=='NAMED_PROTOCOL' and proto.get('protocol',{}).get('name') in ('TCP','UDP','ICMP','ICMPV6'):
            equal=proto['protocol']['name']==flow['protocol'];values.append(not equal if proto.get('matchOpposite') else equal)
        elif proto.get('type')=='PRESET' and proto.get('preset',{}).get('name')=='TCP_UDP':values.append(flow['protocol'] in ('TCP','UDP'))
        else:values.append(None)
    if shape.get('states') is not None:values.append(flow['state'] in shape['states'])
    for endpoint,network,port,ip in zip(shape['endpoints'],(flow.get('source_network'),flow.get('destination_network')),(flow.get('source_port'),flow.get('destination_port')),(flow.get('source_ip'),flow.get('destination_ip'))):
        if endpoint['pending']:values.append(None)
        spec=endpoint.get('addresses')
        if spec is not None:
            try:
                address=ipaddress.ip_address(ip)
                if (address.version==4)!=(flow['ip']=='IPV4'):values.append(None)
                else:
                    found=any(address in ipaddress.ip_network(v) for v in spec['networks'])
                    values.append(not found if spec['matchOpposite'] else found)
            except (ValueError,TypeError):values.append(None)
        spec=endpoint.get('network')
        if spec is not None:
            if not network:values.append(None)
            else:
                found=network in spec['networkIds'];values.append(not found if spec['matchOpposite'] else found)
        spec=endpoint.get('ports')
        if spec is not None:
            if spec.get('type')!='PORTS' or port is None or flow['protocol'] not in ('TCP','UDP'):values.append(None)
            elif any(item.get('type')!='PORT_NUMBER' for item in spec.get('items',[])):values.append(None)
            else:
                found=port in [item['value'] for item in spec['items']];values.append(not found if spec.get('matchOpposite') else found)
    return conjunction(values)

def evaluate(pair,flow,current):
    if not current:return {'status':'unknown','reason':'El catálogo no está vigente. Solicita una lectura.'}
    if not pair or not pair.get('order_unambiguous'):return {'status':'unknown','reason':'No hay un par completo con orden inequívoco.'}
    for policy in pair['policies']:
        if not policy['enabled']:continue
        result=matches(policy,flow)
        if result is False:continue
        if result is None:return {'status':'unknown','policy':policy,'reason':'Esta entrada anterior puede coincidir y tiene criterios sin resolver. No se salta para atribuir la decisión a otra regla.'}
        return {'status':'match','policy':policy,'reason':'Primera coincidencia en el catálogo y los criterios interpretados. No acredita la decisión efectiva del firewall, NAT, ACL, UPnP ni accesibilidad.'}
    return {'status':'unknown','reason':'Ninguna coincidencia interpretada. No se infiere permitir ni bloquear por defecto.'}
