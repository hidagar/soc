"""Reject partial searches before changing reports or durable cursors."""
def complete(result):
    if not isinstance(result,dict) or result.get('timed_out') or result.get('terminated_early'):
        raise ValueError('La consulta Wazuh no está completa.')
    shards=result.get('_shards',{})
    if not isinstance(shards,dict) or shards.get('failed',0)!=0:
        raise ValueError('Hay fragmentos Wazuh sin consultar.')
    return result


def count(value):
    if isinstance(value,bool) or not isinstance(value,int) or value<0:raise ValueError('Recuento Wazuh incompleto.')
    return value


def total(result):
    value=result.get('hits',{}).get('total')
    if not isinstance(value,dict) or value.get('relation','eq')!='eq':raise ValueError('Total Wazuh no exacto.')
    return count(value.get('value'))


def hits(result):
    values=result.get('hits',{}).get('hits')
    if not isinstance(values,list) or any(not isinstance(v,dict) or not isinstance(v.get('_source'),dict) for v in values):
        raise ValueError('Detalle Wazuh incompleto.')
    return values
