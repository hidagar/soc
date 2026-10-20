"""Threat@FLOW layout contrasted with actual StoneOS logs (19 October 2026).

No generic extraction from arbitrary prose: the complete labelled record must
match. Alarm/log-only means no block by this engine, not successful compromise.
"""
import ipaddress
import re

FLOW=re.compile(
    r'\s*from\s+(?P<src>[0-9.]+):(?P<sport>\d{1,5})\((?P<src_interface>[^)\r\n]*)\)\s+'
    r'to\s+(?P<dst>[0-9.]+):(?P<dport>\d{1,5})\((?P<dst_interface>[^)\r\n]*)\),\s*'
    r'threat name:\s*(?P<signature>[^,\r\n]+),\s*threat type:\s*(?P<type>[^,\r\n]+),\s*'
    r'threat subtype:\s*(?P<subtype>[^,\r\n]*),\s*App/Protocol:\s*(?P<protocol>[^,\r\n]*),\s*'
    r'action:\s*(?P<action>[A-Za-z -]+),\s*defender:\s*(?P<defender>[^,\r\n]+),\s*'
    r'severity:\s*(?P<severity>[A-Za-z]+),\s*(?P<reason>[^\r\n]*)\s*',re.I)


def action(value):
    from .event_contract import normalize_action
    return normalize_action('hillstone', value)


def flow(data):
    record=data.get('hillstone',{}) if isinstance(data,dict) else {}
    if not isinstance(record,dict) or str(record.get('category','')).lower()!='threat' or str(record.get('code','')).upper()!='FLOW':
        return None
    message=record.get('message','')
    if not isinstance(message,str) or len(message.encode('utf-16-le',errors='replace'))//2>16384:return None
    match=FLOW.fullmatch(message.strip())
    if not match:return None
    fields={k:v.strip() for k,v in match.groupdict().items()}
    try:
        fields['src']=str(ipaddress.IPv4Address(fields['src']))
        fields['dst']=str(ipaddress.IPv4Address(fields['dst']))
        if any(not 0<=int(fields[key])<=65535 for key in ('sport','dport')):return None
    except (ValueError,TypeError):return None
    for key,limit in (('src_interface',120),('dst_interface',120),('signature',240),('type',80),('subtype',80),('protocol',80),('defender',40),('severity',20)):
        fields[key]=fields[key][:limit]
    # A bounded reputation category distinguishes stable patterns without putting
    # changing IPs/ports/hit counts into the signature.
    risk=re.fullmatch(r'(?:reason:\s*)?hit ip-reputation category ([A-Za-z0-9_-]{1,60}),\s*hit-count:.*',fields['reason'],re.I)
    if fields['signature'].casefold()=='ip-reputation' and risk:
        fields['signature']+=' ('+risk.group(1)+')'
    return fields


def legacy_action_regexp(wanted):
    """Lucene full-field regexp for old indexed records lacking decoded action.

    Label positions exclude text in reason; no leading wildcard that could
    reinterpret an injected later action label. Only observed spellings here.
    """
    from .event_contract import ACTION_VALUES
    def caseword(value):
        return ''.join('['+c.lower()+c.upper()+']' if c.isalpha() else re.escape(c) for c in value)
    choices=r'[A-Za-z \-]+' if wanted=='any' else '|'.join(caseword(v) for v in ACTION_VALUES['hillstone'][wanted])
    octet=r'(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    ipv4='('+octet+r'\.){3}'+octet
    port=r'([0-5]?[0-9]{1,4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'
    return (r'[ ]*'+caseword('from')+r'[ ]+'+ipv4+':'+port+r'\([^)\r\n]*\)[ ]+'+caseword('to')+r'[ ]+'+ipv4+':'+port+r'\([^)\r\n]*\),[ ]*'
        +caseword('threat name:')+r'[ ]*[^,\r\n]+,[ ]*'+caseword('threat type:')+r'[ ]*[^,\r\n]+,[ ]*'
        +caseword('threat subtype:')+r'[ ]*[^,\r\n]*,[ ]*'+caseword('App/Protocol:')+r'[ ]*[^,\r\n]*,[ ]*'
        +caseword('action:')+r'[ ]*('+choices+r')[ ]*,[ ]*'+caseword('defender:')+r'[ ]*[^,\r\n]+,[ ]*'+caseword('severity:')+r'[ ]*[A-Za-z]+,[^\r\n]*')
