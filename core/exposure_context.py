"""Bounded static alias expansion. No DNS, URL downloads or secret persistence."""
import ipaddress
import re

def choices(value):
    if isinstance(value,str):return [v for v in re.split(r'[\s,]+',value.strip()) if v]
    if isinstance(value,dict):
        return [str(k) for k,v in value.items() if isinstance(v,dict) and v.get('selected') in (True,1,'1')]
    return []

def alias_catalog(data):
    items=data.get('alias',{}).get('aliases',{}).get('alias')
    if not isinstance(items,dict) or len(items)>500:raise ValueError('Catálogo no válido o excesivo.')
    aliases={}
    for row in items.values():
        if not isinstance(row,dict):raise ValueError('Alias no válido.')
        name=row.get('name');types=choices(row.get('type'));content=choices(row.get('content'))
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',name) or name in aliases:raise ValueError('Nombre ambiguo.')
        aliases[name]={'enabled':row.get('enabled') in (True,1,'1'),'type':types[0] if len(types)==1 else 'unknown','content':content[:257]}
    return aliases

def expand(value,aliases,kind,trail=()):
    """Return complete literal expansion only, or None for unknown/dynamic/cyclic."""
    if not value:return [] if kind=='port' else None
    if len(trail)>8:return None
    if value in aliases:
        row=aliases[value]
        allowed=('port',) if kind=='port' else ('host','network')
        if value in trail or not row['enabled'] or row['type'] not in allowed or not row['content'] or len(row['content'])>256:return None
        result=[]
        for token in row['content']:
            child=expand(token,aliases,kind,trail+(value,))
            if child is None or len(result)+len(child)>256:return None
            result.extend(child)
        return result
    if kind=='port':
        if value.lower() in ('any','*'):return ['any']
        result=[]
        for token in value.split(','):
            match=re.fullmatch(r'(\d+)(?:[:-](\d+))?',token.strip())
            if not match or not 1<=int(match[1])<=int(match[2] or match[1])<=65535:return None
            result.append(token.strip())
        return result
    if value.lower() in ('any','*'):return ['any']
    try:return [str(ipaddress.ip_network(value,strict=False))]
    except ValueError:return None

def enrich(rule,aliases):
    result=dict(rule);resolutions={};unresolved=[]
    for field,kind in [('source','network'),('destination','network'),('port','port'),('target_port','port')]:
        value=rule[field]
        if value not in aliases:
            if value and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',value) and value.lower() not in ('any','wanip','lanip'):
                unresolved.append(field);resolutions[field]={'alias':value,'status':'unknown'}
            continue
        expanded=expand(value,aliases,kind)
        if expanded is None:unresolved.append(field);resolutions[field]={'alias':value,'status':'unknown'}
        else:
            resolutions[field]={'alias':value,'status':'static','values':expanded}
            if kind=='port':result[field]=','.join(expanded)
            elif any(v in ('any','0.0.0.0/0','::/0') for v in expanded):result[field]='any'
            else:result[field]=','.join(expanded)
    return result,resolutions,unresolved

def interface_catalog(data):
    items=data.get('interfaces',{}).get('items')
    if not isinstance(items,list) or len(items)>64:raise ValueError('Interfaces no válidas.')
    result=[]
    for row in items:
        if not isinstance(row,dict):raise ValueError('Interfaz no válida.')
        # OPNsense uses id/text for select2 interface options.
        identity=row.get('id',row.get('value'));label=row.get('text',row.get('label'))
        if not isinstance(identity,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',identity) or not isinstance(label,str):raise ValueError('Interfaz sin identidad.')
        result.append({'id':identity,'label':label[:80]})
    return result
