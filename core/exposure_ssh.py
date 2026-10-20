"""Fixed read-only OPNsense SSH reader; emits only whitelisted legacy settings."""
import json
from .ssh_connection import run_command
from .exposure_context import alias_catalog

SCRIPT=r'''<?php
try {
    if (!is_readable('/conf/config.xml')) { echo json_encode(['status'=>'error','reason'=>'permissions']);exit(1); }
    $xml=simplexml_load_file('/conf/config.xml', 'SimpleXMLElement', LIBXML_NONET);
    if ($xml===false) { throw new Exception('configuration'); }
    $out=['status'=>'ok','filter'=>[],'nat'=>[],'aliases'=>[],'interfaces'=>[]];
    foreach (['filter','nat'] as $section) {
        if (!isset($xml->{$section})) { throw new Exception('missing section'); }
        foreach ($xml->{$section}->rule as $index=>$rule) {
            if (count($out[$section])>=200) { throw new Exception('limit'); }
            $source=isset($rule->source->any)?'any':(string)($rule->source->address ?: $rule->source->network);
            $destination=isset($rule->destination->any)?'any':(string)($rule->destination->address ?: $rule->destination->network);
            $row=['uuid'=>'','enabled'=>isset($rule->disabled)?'0':'1','disabled'=>isset($rule->disabled)?'1':'0',
                'description'=>(string)$rule->descr,'descr'=>(string)$rule->descr,
                'interface'=>(string)$rule->interface,'action'=>(string)$rule->type,
                'direction'=>(string)$rule->direction ?: 'in','protocol'=>(string)$rule->protocol,
                'source_net'=>$source,'source.address'=>$source,
                'source_not'=>isset($rule->source->not)?'1':'0','source.not'=>isset($rule->source->not)?'1':'0',
                'destination_net'=>$destination,'destination_port'=>(string)$rule->destination->port,
                'destination.port'=>(string)$rule->destination->port,
                'destination_not'=>isset($rule->destination->not)?'1':'0','destination.not'=>isset($rule->destination->not)?'1':'0',
                'target'=>(string)$rule->target,'local-port'=>(string)$rule->{'local-port'},
                'log'=>isset($rule->log)?'1':'0','nordr'=>isset($rule->nordr)?'1':'0','interfacenot'=>isset($rule->interfacenot)?'1':'0'];
            $row['uuid']='ssh-legacy-'.$section.'-'.count($out[$section]).'-'.substr(hash('sha256',json_encode($row)),0,24);
            $out[$section][]=$row;
        }
    }
    foreach ($xml->OPNsense->Firewall->Alias->aliases->alias ?? [] as $alias) {
        if (count($out['aliases'])>=200) { throw new Exception('limit'); }
        $out['aliases'][]=['enabled'=>(string)$alias->enabled,'name'=>(string)$alias->name,'type'=>(string)$alias->type,'content'=>(string)$alias->content];
    }
    foreach ($xml->interfaces->children() as $id=>$item) {
        $out['interfaces'][]=['id'=>$id,'label'=>(string)$item->descr];
    }
    echo json_encode($out);
} catch (Throwable $error) { echo json_encode(['status'=>'error']);exit(1); }
'''

def read_legacy(connection):
    command='/usr/local/bin/php -f /dev/stdin'
    status,output,_=run_command(connection,command,stdin_data=SCRIPT.encode())
    try:data=json.loads(output)
    except (TypeError,ValueError):raise ValueError('Respuesta SSH no válida.')
    if isinstance(data,dict) and data.get('status')=='error' and data.get('reason')=='permissions':
        status,output,_=run_command(connection,'sudo -n '+command,stdin_data=SCRIPT.encode())
        try:data=json.loads(output)
        except (TypeError,ValueError):raise ValueError('No se dispone de lectura de configuración ni sudo sin interacción.')
    if status or not isinstance(data,dict) or data.get('status')!='ok':raise ValueError('Lectura no confirmada.')
    for section in ('filter','nat','aliases','interfaces'):
        if not isinstance(data.get(section),list) or len(data[section])>200 or any(not isinstance(row,dict) for row in data[section]):raise ValueError('Listado parcial o excesivo.')
    aliases=alias_catalog({'alias':{'aliases':{'alias':{str(i):row for i,row in enumerate(data['aliases'])}}}})
    return data,aliases
