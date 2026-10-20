(()=>{'use strict';
const root=document.getElementById('threat-console');if(!root)return;
const $=id=>document.getElementById(id),NS='http://www.w3.org/2000/svg',colors={blocked:'#66e7d6',allowed:'#ffbf70',unknown:'#a09cf4'};
const actionLabel={blocked:'Bloqueada',allowed:'Permitida',unknown:'Sin confirmar'},directionLabel={inbound:'Origen externo → red privada',outbound:'Destino externo · conexión saliente',external:'Origen público · dirección sin confirmar',internal:'Sin IP pública',pending:'Geolocalización pendiente'};
const num=x=>Number(x||0).toLocaleString('es-ES');
let payload=JSON.parse($('threat-map-payload').textContent),features=[],country=null,busy=false;
const motionQuery=window.matchMedia('(prefers-reduced-motion: reduce)');
let motionPaused=motionQuery.matches,lastSuccess=Date.now(),lastAttempt=Date.now(),networkFailed=false,liveIndex=0;
let serverTime=Date.parse(payload.generated_at_iso)||Date.now();
let seenIds=new Set((payload.recent||[]).map(e=>e.uid).filter(Boolean)),freshIds=new Set();
function watchMode(){return document.body.classList.contains('map-presentation')||document.fullscreenElement===$('map-panel')||fullscreenFallback;}
function refreshDelay(){return watchMode()?15000:60000;}
function eventAge(event){const t=Date.parse(event.observed_at);return Number.isFinite(t)?Math.max(0,serverTime+Date.now()-lastSuccess-t):null;}
function ageText(ms){if(ms===null)return 'Hora sin confirmar';if(ms<60000)return 'hace menos de 1 min';if(ms<3600000)return `hace ${Math.floor(ms/60000)} min`;return `hace ${Math.floor(ms/3600000)} h`;}
function updateWatchClock(){
 $('noc-clock').textContent=new Date().toLocaleTimeString('es-ES',{hour12:false,timeZone:'Europe/Madrid'});
 const seconds=Math.floor((Date.now()-lastSuccess)/1000),stale=networkFailed||seconds>refreshDelay()/1000*3;
 const watch=payload.watch||{};
 $('map-panel').classList.toggle('noc-stale',stale);
 $('map-panel').classList.toggle('noc-attention',!stale&&((watch.allowed||0)>0||(watch.critical||0)>0));
 $('map-panel').classList.toggle('noc-critical',!stale&&(watch.critical||0)>0);
 $('noc-state').textContent=stale?'Datos sin actualizar':watch.critical?'Revisar detecciones de nivel alto':watch.allowed?'Revisar detecciones permitidas':watch.total?'Actividad recibida':'Sin detecciones recientes';
 $('noc-freshness').textContent=`Última consulta correcta: hace ${seconds} s · consulta cada ${refreshDelay()/1000} s`;
 $('map-updated').textContent=stale?'Actualización pendiente · conservamos los últimos datos':`Actualizado ${payload.generated_at} · consulta cada ${refreshDelay()/1000} s`;
}
function spotlightCountry(code){
 $('map-land').querySelectorAll('path').forEach(p=>p.classList.toggle('noc-spotlight',Boolean(code)&&p.dataset.code===code));
}
function renderWatch(advance=false){
 const watch=payload.watch||{};
 $('noc-total').textContent=num(watch.total);$('noc-allowed').textContent=num(watch.allowed);$('noc-critical').textContent=num(watch.critical);
 const events=(payload.recent||[]).filter(e=>!country||e.country_code===country);
 if(advance)liveIndex++;
 if(liveIndex>=events.length)liveIndex=0;
 const event=events[liveIndex],card=$('noc-event');
 card.classList.toggle('noc-event-new',Boolean(event&&freshIds.has(event.uid)));
 card.classList.toggle('noc-event-allowed',Boolean(event&&event.action==='allowed'));
 if(event){
  const age=eventAge(event),recent=age!==null&&age<15*60000;
  $('noc-event-label').textContent=recent?'Actividad reciente registrada':'Histórico del filtro';
  $('noc-event-title').textContent=event.signature||'Detección de seguridad';
  const priority={low:'baja',medium:'media',high:'alta',critical:'crítica'}[event.soc_priority]||'sin versión registrada';
  $('noc-event-detail').textContent=`${event.client} · ${event.site} · ${event.device} · ${event.country} · ${actionLabel[event.action]||'Sin confirmar'} · nivel Wazuh ${Number(event.level||0)} · prioridad SOC ${priority} · ${ageText(age)} (${event.time})`;
  spotlightCountry(event.country_code);
 }else{
  $('noc-event-label').textContent='Vigilancia del filtro';
  $('noc-event-title').textContent=watch.total?'Actividad agregada recibida':'Sin detecciones en los últimos 15 minutos';
  $('noc-event-detail').textContent=payload.last_event?'Última detección del periodo: '+payload.last_event:'La ausencia de alertas no acredita el estado del envío de logs.';
  spotlightCountry(null);
 }
 updateWatchClock();
}
function setMotion(paused){
 motionPaused=paused;root.classList.toggle('map-motion-paused',paused);
 $('map-motion').textContent=paused?'Reanudar animación':'Pausar animación';$('map-motion').setAttribute('aria-pressed',String(paused));
}
$('map-motion').addEventListener('click',()=>setMotion(!motionPaused));
motionQuery.addEventListener('change',event=>setMotion(event.matches));
setMotion(motionPaused);

function svg(tag,attrs){const e=document.createElementNS(NS,tag);Object.entries(attrs||{}).forEach(([k,v])=>e.setAttribute(k,v));return e;}
function element(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function project(lon,lat){return [(lon+180)/360*1000,(90-lat)/180*500+15];}
function path(rings){return rings.map(ring=>ring.map((p,i)=>{const xy=project(p[0],p[1]);return (i?'L':'M')+xy.map(v=>v.toFixed(1)).join(',');}).join(' ')+'Z').join(' ');}
function drawWorld(){const land=$('map-land');land.replaceChildren();features.forEach(f=>{const polygons=f.geometry.type==='Polygon'?[f.geometry.coordinates]:f.geometry.coordinates;const p=svg('path',{d:polygons.map(path).join(' '),'class':'map-country','data-code':f.properties.code});const title=svg('title');title.textContent=f.properties.name;p.append(title);land.append(p);});const grid=$('map-grid');for(let lon=-180;lon<=180;lon+=30){const [x]=project(lon,0);grid.append(svg('line',{x1:x,x2:x,y1:15,y2:515,class:'map-gridline'}));}for(let lat=-60;lat<=60;lat+=30){const [,y]=project(0,lat);grid.append(svg('line',{x1:0,x2:1000,y1:y,y2:y,class:'map-gridline'}));}}
function choose(code){country=country===code?null:code;render();}
function renderMarkers(){const markers=$('map-markers');markers.replaceChildren();$('map-land').querySelectorAll('path').forEach(p=>p.classList.toggle('active',payload.countries.some(c=>c.code===p.dataset.code)));const grouped=new Map();payload.points.forEach(p=>{if(country&&p.code!==country)return;const current=grouped.get(p.code)||{...p,count:0,blocked:0,allowed:0,unknown:0,recent_count:0};current.count+=p.count;current.recent_count=(current.recent_count||0)+(p.recent_count||0);current[p.action in colors?p.action:'unknown']+=p.count;grouped.set(p.code,current);});grouped.forEach(p=>{const f=features.find(f=>f.properties.code===p.code),label=f&&f.properties.label;const [x,y]=project(label&&Number.isFinite(label[0])?label[0]:p.lon,label&&Number.isFinite(label[1])?label[1]:p.lat);const radius=Math.min(19,5+Math.sqrt(p.count)*1.5),color=p.allowed?colors.allowed:p.blocked?colors.blocked:colors.unknown;const group=svg('g',{class:'map-marker'+(p.recent_count>0?' is-recent':''),transform:`translate(${x},${y})`,tabindex:'0',role:'button','aria-label':`${p.country}: ${p.count} detecciones`});group.append(svg('circle',{r:radius+5,fill:'none',stroke:color,'stroke-width':1,class:'pulse'}),svg('circle',{r:radius,fill:color,'fill-opacity':'.2',stroke:color,'stroke-width':1.5}),svg('circle',{r:2.5,fill:color}));if(p.count>1){const t=svg('text',{x:radius+4,y:3});t.textContent=num(p.count);group.append(t);}const title=svg('title');title.textContent=`${p.country} · ${num(p.count)} detecciones · ${num(p.blocked)} bloqueadas · ${num(p.allowed)} permitidas`;group.append(title);group.addEventListener('click',()=>choose(p.code));group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choose(p.code);}});const show=()=>{const tip=$('map-tooltip');tip.replaceChildren(element('strong',p.country),element('small',`${num(p.count)} detecciones · ${num(p.blocked)} bloqueadas · ${num(p.allowed)} permitidas`));tip.hidden=false;};group.addEventListener('mouseenter',show);group.addEventListener('focus',show);group.addEventListener('mouseleave',()=>{$('map-tooltip').hidden=true;});group.addEventListener('blur',()=>{$('map-tooltip').hidden=true;});markers.append(group);});$('map-empty').hidden=grouped.size>0;}
function render(){for(const [id,value] of Object.entries({'kpi-total':payload.total,'kpi-blocked':payload.blocked,'kpi-allowed':payload.allowed,'kpi-countries':payload.countries.length}))$(id).textContent=num(value);
$('kpi-period').textContent=payload.days===1?'Últimas 24 horas':`Últimos ${payload.days} días`;$('map-window').textContent=payload.days===1?'24 HORAS':payload.days+' DÍAS';
$('kpi-coverage').textContent=`${num(payload.located)} eventos geolocalizados`;
$('map-updated').textContent='Actualizado '+payload.generated_at+' · refresco cada 60 s';
$('geo-summary').textContent=`${num(payload.located)} geolocalizados · ${num(payload.private)} sin IP pública · ${num(payload.unknown_location)} ubicación desconocida · ${num(payload.pending)} pendientes`+(payload.limited?' · Volumen limitado a los 20.000 eventos más recientes.':'');
if(payload.geo_error)$('geo-summary').textContent+=' · '+payload.geo_error;
if(payload.history_pending)$('geo-summary').textContent+=' · Recuperación de los últimos 30 días en curso.';
if(payload.geo_database)$('geo-summary').textContent+=' · Base GeoIP: '+payload.geo_database;
const rank=$('country-ranking');rank.replaceChildren();const max=payload.countries[0]?.count||1;payload.countries.slice(0,8).forEach(c=>{const b=element('button',undefined,'country-row');b.type='button';const top=element('span',undefined,'country-top');top.append(element('span',c.name),element('strong',num(c.count)));const bar=element('span',undefined,'country-bar'),fill=element('i');fill.style.width=(c.count/max*100)+'%';bar.append(fill);b.append(top,bar);b.addEventListener('click',()=>choose(c.code));rank.append(b);});if(!payload.countries.length)rank.append(element('p','Sin países identificados en este periodo.','insight-hint'));
$('clear-country').hidden=!country;const explore=$('explore-country');if(explore){const params=new URLSearchParams(window.location.search);if(country)params.set('country',country);else params.delete('country');explore.href=root.dataset.explore+'?'+params.toString();explore.textContent=country?'Investigar eventos de este país':'Investigar todos los eventos del filtro';}const timeline=$('map-timeline');timeline.replaceChildren();const peak=Math.max(1,...payload.timeline.map(t=>t.count));payload.timeline.forEach((t,i)=>{const d=element('div',undefined,'day');d.title=`${t.date}: ${num(t.count)} detecciones`;const bar=element('span',undefined,'bar');bar.style.height=Math.max(2,t.count/peak*60)+'px';d.append(bar,element('small',payload.days<=7||i%5===0?t.date:''));timeline.append(d);});
const engines=$('map-engines');engines.replaceChildren();Object.entries(payload.engines).forEach(([engine,count])=>{const row=element('div',undefined,'engine-row');row.append(element('span',({unifi:'UniFi CyberSecure',zenarmor:'Zenarmor',suricata:'Suricata'})[engine]||engine),element('strong',num(count)));engines.append(row);});$('last-event').textContent=payload.last_event?'Última detección recibida: '+payload.last_event:'Sin detecciones recibidas en este periodo.';
const tbody=$('map-events-body');tbody.replaceChildren();const selected=country?payload.countries.find(c=>c.code===country):null;$('events-title').textContent=selected?'Detecciones recientes · '+selected.name:'Detecciones recientes';payload.recent.filter(e=>!selected||e.country===selected.name).forEach(e=>{const row=element('tr');row.append(element('td',e.time));const client=element('td',e.client);client.append(element('small',e.site+' / '+e.device));row.append(client);const detection=element('td');if(e.incident_url){const a=element('a',e.signature);a.href=e.incident_url;detection.append(a);}else detection.textContent=e.signature;row.append(detection);const geo=element('td',e.country);geo.append(element('small',directionLabel[e.direction]||'Dirección sin confirmar'));row.append(geo);const asset=element('td',undefined,'technical-detail');if(e.peer&&root.dataset.investigate){const a=element('a',e.peer),params=new URLSearchParams(window.location.search);params.set('ip',e.peer);if(e.client_id)params.set('client',e.client_id);params.delete('country');params.delete('direction');params.delete('action');a.href=root.dataset.investigate+'?'+params.toString();asset.append(a);}else asset.textContent=e.peer||'Sin IP pública';asset.append(element('small',e.asset+(e.asset_ip&&e.asset!==e.asset_ip?' · '+e.asset_ip:'')));row.append(asset);const action=element('td');action.append(element('span',actionLabel[e.action]||'Sin confirmar','event-badge '+(e.action in colors?e.action:'unknown')));row.append(action);tbody.append(row);});if(!tbody.childElementCount){const tr=element('tr'),td=element('td',country?'No hay eventos de este país entre los últimos 20 del filtro.':'Sin detecciones recibidas en este periodo.');td.colSpan=6;tr.append(td);tbody.append(tr);}renderMarkers();renderWatch();}
const mapPanel=$('map-panel'),fullscreenButton=$('map-fullscreen');
let fullscreenFallback=false;
function syncFullscreen(){
 const active=document.fullscreenElement===mapPanel||fullscreenFallback;
 fullscreenButton.textContent=active?'Salir de pantalla completa':'Pantalla completa';
 fullscreenButton.setAttribute('aria-pressed',String(active));
 $('map-fullscreen-hint').hidden=!active;
}
function exitFullscreenFallback(){
 fullscreenFallback=false;mapPanel.classList.remove('is-fullscreen');
 document.body.classList.remove('map-fullscreen-fallback');syncFullscreen();
 fullscreenButton.focus({preventScroll:true});
}
fullscreenButton.addEventListener('click',async()=>{
 if(fullscreenFallback){exitFullscreenFallback();return;}
 if(document.fullscreenElement===mapPanel){await document.exitFullscreen();return;}
 fullscreenButton.disabled=true;
 try{
  if(!mapPanel.requestFullscreen)throw new Error('Fullscreen unavailable');
  await mapPanel.requestFullscreen();
 }catch(_){
  fullscreenFallback=true;mapPanel.classList.add('is-fullscreen');
  document.body.classList.add('map-fullscreen-fallback');
 }finally{fullscreenButton.disabled=false;syncFullscreen();}
});
document.addEventListener('fullscreenchange',()=>{syncFullscreen();if(!document.fullscreenElement)fullscreenButton.focus({preventScroll:true});});
document.addEventListener('keydown',event=>{
 if(event.key==='Escape'&&document.fullscreenElement===mapPanel){event.preventDefault();document.exitFullscreen().catch(()=>{});return;}
 if(!fullscreenFallback)return;
 if(event.key==='Escape'){event.preventDefault();exitFullscreenFallback();}
 if(event.key==='Tab'){
  const focusable=[...mapPanel.querySelectorAll('button:not([disabled]),a[href],[tabindex="0"]')].filter(item=>item.getClientRects().length);
  const first=focusable[0],last=focusable[focusable.length-1];
  if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
 }
});
function setPresentation(active){document.body.classList.toggle('map-presentation',active);$('presentation-toggle').textContent=active?'Salir de presentación NOC':'Modo presentación · NOC';$('presentation-toggle').setAttribute('aria-pressed',String(active));try{sessionStorage.setItem('soc-map-noc',active?'1':'0');}catch(_){}updateWatchClock();}
$('clear-country').addEventListener('click',()=>{country=null;render();});
$('presentation-toggle').addEventListener('click',()=>{setPresentation(!document.body.classList.contains('map-presentation'));refresh();});
try{setPresentation(sessionStorage.getItem('soc-map-noc')==='1');}catch(_){}
$('map-print').addEventListener('click',()=>window.print());
fetch(root.dataset.world,{credentials:'same-origin'}).then(r=>{if(!r.ok)throw Error();return r.json();}).then(world=>{features=world.features;drawWorld();render();}).catch(()=>{$('map-empty').hidden=false;$('map-empty').textContent='No se pudo cargar la cartografía. Los contadores siguen disponibles.';});render();
async function refresh(){
 if(busy||document.hidden)return;busy=true;lastAttempt=Date.now();
 const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),20000);
 try{
  const r=await fetch(root.dataset.endpoint+window.location.search,{credentials:'same-origin',headers:{Accept:'application/json'},cache:'no-store',signal:controller.signal});
  if(!r.ok||!r.headers.get('content-type')?.includes('application/json'))throw Error();
  const next=await r.json();
  if(!Array.isArray(next.recent)||!Array.isArray(next.points)||!next.watch)throw Error();
  freshIds=new Set(next.recent.filter(e=>e.uid&&!seenIds.has(e.uid)&&Date.parse(e.observed_at)>=Date.parse(next.generated_at_iso)-15*60000).map(e=>e.uid));
  next.recent.forEach(e=>{if(e.uid)seenIds.add(e.uid);});
  if(seenIds.size>1000)seenIds=new Set(next.recent.map(e=>e.uid).filter(Boolean));
  payload=next;lastSuccess=Date.now();serverTime=Date.parse(next.generated_at_iso)||Date.now();networkFailed=false;liveIndex=0;render();
 }catch(_){networkFailed=true;updateWatchClock();}finally{clearTimeout(timeout);busy=false;}
}
setInterval(()=>{if(Date.now()-lastAttempt>=refreshDelay())refresh();},1000);
setInterval(()=>{if(!document.hidden)updateWatchClock();},1000);
setInterval(()=>{if(!document.hidden&&!motionPaused)renderWatch(true);},8000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&Date.now()-lastSuccess>=refreshDelay())refresh();});
})();
