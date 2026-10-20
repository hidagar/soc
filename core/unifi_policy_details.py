"""Bounded display of observed UniFi port/protocol types; not a flow evaluator."""
from .unifi_zone_scope import boolean, integer, sequence, identity
import ipaddress


def addresses(spec):
    """Only the literal IP_ADDRESS/SUBNET layout observed on Network 10.6."""
    if not isinstance(spec,dict) or spec.get('type')!='IP_ADDRESSES':
        return None
    inverse=boolean(spec.get('matchOpposite'))
    values=sequence(spec.get('items'),250)
    if not values:raise ValueError('Empty address selection')
    networks=[]
    pending=bool(set(spec)-{'type','matchOpposite','items'})
    for item in values:
        if not isinstance(item,dict) or set(item)!={'type','value'} or item.get('type') not in ('IP_ADDRESS','SUBNET'):
            return None
        value=item['value']
        if not isinstance(value,str) or len(value)>80 or '%' in value:raise ValueError('Unknown IP literal')
        if item['type']=='IP_ADDRESS':
            ip=ipaddress.ip_address(value);network=ipaddress.ip_network(str(ip))
        else:
            if '/' not in value:raise ValueError('Subnet without prefix')
            network=ipaddress.ip_network(value,strict=False)
        networks.append(str(network))
    if len(set(networks))!=len(networks):raise ValueError('Duplicate address')
    return {'networks':sorted(networks),'matchOpposite':inverse,'pending':pending}


def ports(spec, objects):
    if not isinstance(spec, dict): raise ValueError('Unknown port filter')
    inverse = boolean(spec.get('matchOpposite'))
    kind = spec.get('type')
    prefix = 'excepto ' if inverse else ''
    if kind == 'TRAFFIC_MATCHING_LIST':
        obj = objects.get(identity(spec.get('trafficMatchingListId')))
        pending = bool(set(spec) - {'type','matchOpposite','trafficMatchingListId'})
        if not obj or obj.get('type') != 'PORTS': return 'objeto de puertos sin identificar', True
        return prefix + obj['name'] + f" ({obj['count']} entradas)", pending
    if kind != 'PORTS': return 'filtro de puertos específico; revisar en UniFi', True
    values = sequence(spec.get('items'), 250)
    if not values: raise ValueError('Empty port selection')
    numbers = []
    pending = bool(set(spec) - {'type','matchOpposite','items'})
    for item in values:
        if not isinstance(item, dict): raise ValueError('Unknown port item')
        if item.get('type') != 'PORT_NUMBER' or set(item) != {'type','value'}:
            return 'puertos o rangos específicos; revisar en UniFi', True
        value = integer(item['value'])
        if not 1 <= value <= 65535: raise ValueError('Port out of range')
        numbers.append(value)
    if len(set(numbers)) != len(numbers): raise ValueError('Duplicate port')
    return prefix + ', '.join(str(v) for v in sorted(numbers)), pending


def protocol(scope):
    spec = scope.get('protocolFilter')
    pending = bool(set(scope) - {'ipVersion','protocolFilter'})
    if spec is None: return 'Todos los protocolos en el ámbito IP declarado', pending
    if not isinstance(spec, dict): raise ValueError('Unknown protocol filter')
    kind = spec.get('type')
    if kind == 'NAMED_PROTOCOL':
        item = spec.get('protocol')
        if not isinstance(item, dict): raise ValueError('Unknown named protocol')
        pending |= bool(set(spec) - {'type','protocol','matchOpposite'} or set(item) != {'name'})
        inverse = boolean(spec.get('matchOpposite'))
        value = item.get('name')
        if value not in ('TCP','UDP','ICMP','ICMPV6'):
            return 'Protocolo específico; revisar en UniFi', True
        return ('Todos excepto ' if inverse else '') + value, pending
    if kind == 'PRESET':
        item = spec.get('preset')
        if not isinstance(item, dict): raise ValueError('Unknown protocol preset')
        if item.get('name') != 'TCP_UDP': return 'Grupo de protocolos específico; revisar en UniFi', True
        pending |= bool(set(spec) - {'type','preset'} or set(item) != {'name'})
        return 'TCP y UDP', pending
    return 'Protocolo específico; revisar en UniFi', True
