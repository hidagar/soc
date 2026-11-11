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
// El portal del cliente fija un mínimo (data-min-refresh): su modo presentación no consulta cada 15 s.
function refreshDelay(){const minimum=Number($('threat-console').dataset.minRefresh||0);return Math.max(minimum,watchMode()?15000:60000);}
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
$('map-motion').addEventListener('click',()=>{setMotion(!motionPaused);if(features.length)renderMarkers();});
motionQuery.addEventListener('change',event=>setMotion(event.matches));
setMotion(motionPaused);

function svg(tag,attrs){const e=document.createElementNS(NS,tag);Object.entries(attrs||{}).forEach(([k,v])=>e.setAttribute(k,v));return e;}
function element(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function project(lon,lat){return [(lon+180)/360*1000,(90-lat)/180*500+15];}
function path(rings){return rings.map(ring=>ring.map((p,i)=>{const xy=project(p[0],p[1]);return (i?'L':'M')+xy.map(v=>v.toFixed(1)).join(',');}).join(' ')+'Z').join(' ');}
function drawWorld(){const land=$('map-land');land.replaceChildren();features.forEach(f=>{const polygons=f.geometry.type==='Polygon'?[f.geometry.coordinates]:f.geometry.coordinates;const p=svg('path',{d:polygons.map(path).join(' '),'class':'map-country','data-code':f.properties.code});const title=svg('title');title.textContent=f.properties.name;p.append(title);land.append(p);});const grid=$('map-grid');for(let lon=-180;lon<=180;lon+=30){const [x]=project(lon,0);grid.append(svg('line',{x1:x,x2:x,y1:15,y2:515,class:'map-gridline'}));}for(let lat=-60;lat<=60;lat+=30){const [,y]=project(0,lat);grid.append(svg('line',{x1:0,x2:1000,y1:y,y2:y,class:'map-gridline'}));}}
function choose(code){country=country===code?null:code;render();}
// --- Vista: zoom y desplazamiento. La base recorta la Antártida para dar más tamaño a lo que importa.
const BASE={x:0,y:28,w:1000,h:420};let view={...BASE};
function zoomLevel(){return BASE.w/view.w;}
function clampView(){view.w=Math.max(BASE.w/10,Math.min(BASE.w,view.w));view.h=view.w*BASE.h/BASE.w;view.x=Math.max(BASE.x,Math.min(BASE.x+BASE.w-view.w,view.x));view.y=Math.max(BASE.y,Math.min(BASE.y+BASE.h-view.h,view.y));}
function applyView(){clampView();$('world-map').setAttribute('viewBox',`${view.x.toFixed(1)} ${view.y.toFixed(1)} ${view.w.toFixed(1)} ${view.h.toFixed(1)}`);$('map-zoom-reset').disabled=zoomLevel()<1.02;$('map-zoom-out').disabled=zoomLevel()<1.02;$('world-stage').classList.toggle('is-zoomed',zoomLevel()>1.02);if(features.length)renderMarkers();}
function zoomAt(factor,cx,cy){const rx=(cx-view.x)/view.w,ry=(cy-view.y)/view.h;view.w=view.w/factor;clampView();view.x=cx-rx*view.w;view.y=cy-ry*view.h;applyView();}
function mapPoint(event){const map=$('world-map'),pt=map.createSVGPoint();pt.x=event.clientX;pt.y=event.clientY;const m=map.getScreenCTM();if(!m)return [view.x+view.w/2,view.y+view.h/2];const r=pt.matrixTransform(m.inverse());return [r.x,r.y];}
function zoomCenter(factor){zoomAt(factor,view.x+view.w/2,view.y+view.h/2);}
function focusRegion(lon1,lat1,lon2,lat2){const a=project(lon1,lat1),b=project(lon2,lat2);view.w=Math.max(Math.abs(b[0]-a[0]),Math.abs(b[1]-a[1])*BASE.w/BASE.h);clampView();view.x=(a[0]+b[0])/2-view.w/2;view.y=(a[1]+b[1])/2-view.h/2;applyView();}
function mix(a,b,t){return '#'+[0,1,2].map(k=>Math.round(a[k]+(b[k]-a[k])*t).toString(16).padStart(2,'0')).join('');}
function pointFor(p){const f=features.find(f=>f.properties.code===p.code),label=f&&f.properties.label;return project(label&&Number.isFinite(label[0])?label[0]:p.lon,label&&Number.isFinite(label[1])?label[1]:p.lat);}
// --- Líneas de ataque: del país a la zona de las sedes protegidas (o al revés, si son conexiones salientes).
function renderArcs(list){const layer=$('map-arcs');layer.replaceChildren();const home=payload.home;if(!home||!list.length)return;const [hx,hy]=project(home.lon,home.lat),z=zoomLevel(),scale=1/Math.pow(z,.7);
 const shown=list.slice().sort((a,b)=>b.count-a.count).filter((p,i)=>i<14||p.recent_count>0),max=shown[0].count||1;
 shown.forEach(p=>{const [x,y]=p.xy,dist=Math.hypot(hx-x,hy-y);if(dist<5)return;const lift=Math.min(95,dist*.3),mx=(x+hx)/2,my=(y+hy)/2-lift,outbound=p.outbound>p.inbound;
  const d=outbound?`M${hx.toFixed(1)},${hy.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${x.toFixed(1)},${y.toFixed(1)}`:`M${x.toFixed(1)},${y.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${hx.toFixed(1)},${hy.toFixed(1)}`;
  const share=Math.sqrt(p.count/max),color=p.allowed?colors.allowed:p.blocked?colors.blocked:colors.unknown;
  layer.append(svg('path',{d,class:'map-arc'+(p.recent_count>0?' is-recent':'')+(outbound?' is-outbound':''),stroke:color,'stroke-width':((.5+1.9*share)*scale).toFixed(2),'stroke-opacity':(.22+.5*share).toFixed(2)}));
  if(p.recent_count>0&&!motionPaused){const dot=svg('circle',{r:(2.4*scale).toFixed(2),fill:color,class:'map-arc-dot'}),motion=svg('animateMotion',{dur:(1.8+dist/260).toFixed(1)+'s',repeatCount:'indefinite',path:d});dot.append(motion);layer.append(dot);}});
 const g=svg('g',{class:'map-home',transform:`translate(${hx.toFixed(1)},${hy.toFixed(1)}) scale(${scale.toFixed(3)})`});g.append(svg('circle',{r:9,class:'map-home-ring'}),svg('circle',{r:3.2,class:'map-home-dot'}));if(z>=1.8){const label=svg('text',{x:0,y:-13,'text-anchor':'middle'});label.textContent=root.dataset.homeLabel||'Sedes protegidas';g.append(label);}const title=svg('title');title.textContent='Zona aproximada de las sedes protegidas. Las líneas son ilustrativas: unen cada país con esta zona.';g.append(title);layer.append(g);}
function renderMarkers(){const markers=$('map-markers');markers.replaceChildren();
 const byCode=new Map(payload.countries.map(c=>[c.code,c])),top=Math.log((payload.countries[0]?.count||0)+1)||1;
 $('map-land').querySelectorAll('path').forEach(p=>{const c=byCode.get(p.dataset.code);p.classList.toggle('active',Boolean(c));p.classList.toggle('is-dimmed',Boolean(country)&&p.dataset.code!==country);p.style.fill=c?mix([29,70,85],[42,118,116],Math.log(c.count+1)/top):'';});
 const grouped=new Map();payload.points.forEach(p=>{if(country&&p.code!==country)return;const current=grouped.get(p.code)||{...p,count:0,blocked:0,allowed:0,unknown:0,recent_count:0,inbound:0,outbound:0};current.count+=p.count;current.recent_count+=(p.recent_count||0);current[p.action in colors?p.action:'unknown']+=p.count;current[p.direction==='outbound'?'outbound':'inbound']+=p.count;grouped.set(p.code,current);});
 const z=zoomLevel(),scale=1/Math.pow(z,.7),list=[...grouped.values()];list.forEach(p=>{p.xy=pointFor(p);});
 renderArcs(list);
 list.sort((a,b)=>b.count-a.count).forEach(p=>{const [x,y]=p.xy,radius=Math.min(19,5+Math.sqrt(p.count)*1.5),base=p.blocked?colors.blocked:p.allowed?colors.allowed:colors.unknown;
  const group=svg('g',{class:'map-marker'+(p.recent_count>0?' is-recent':''),transform:`translate(${x.toFixed(1)},${y.toFixed(1)}) scale(${scale.toFixed(3)})`,tabindex:'0',role:'button','aria-label':`${p.country}: ${p.count} detecciones, ${p.allowed} permitidas`});
  group.append(svg('circle',{r:radius+5,fill:'none',stroke:base,'stroke-width':1,class:'pulse'}),svg('circle',{r:radius,fill:base,'fill-opacity':'.2',stroke:base,'stroke-width':1.5}));
  if(p.allowed&&p.blocked+p.unknown>0){const circumference=2*Math.PI*radius,part=Math.max(.08,p.allowed/p.count)*circumference;group.append(svg('circle',{r:radius,fill:'none',stroke:colors.allowed,'stroke-width':2.6,'stroke-dasharray':`${part.toFixed(1)} ${(circumference-part).toFixed(1)}`,transform:'rotate(-90)',class:'map-marker-share'}));}
  group.append(svg('circle',{r:2.5,fill:p.allowed?colors.allowed:base}));
  if(p.count>1){const t=svg('text',{x:radius+4,y:3});t.textContent=num(p.count);group.append(t);}
  const summary=`${num(p.count)} detecciones · ${num(p.blocked)} bloqueadas · ${num(p.allowed)} permitidas`+(p.outbound?` · ${num(p.outbound)} conexiones salientes`:'');
  const title=svg('title');title.textContent=`${p.country} · ${summary}`;group.append(title);
  group.addEventListener('click',()=>{if(!dragged)choose(p.code);});group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choose(p.code);}});
  const show=()=>{const tip=$('map-tooltip');tip.replaceChildren(element('strong',p.country),element('small',summary),element('small',p.recent_count?`${num(p.recent_count)} en los últimos 15 minutos`:'Sin actividad en los últimos 15 minutos'));tip.hidden=false;};
  group.addEventListener('mouseenter',show);group.addEventListener('focus',show);group.addEventListener('mouseleave',()=>{$('map-tooltip').hidden=true;});group.addEventListener('blur',()=>{$('map-tooltip').hidden=true;});markers.append(group);});
 $('map-empty').hidden=grouped.size>0;}
let dragged=false;
(function(){const stage=$('world-stage');let start=null;
 $('map-zoom-in').addEventListener('click',()=>zoomCenter(1.6));$('map-zoom-out').addEventListener('click',()=>zoomCenter(1/1.6));$('map-zoom-reset').addEventListener('click',()=>{view={...BASE};applyView();});
 $('map-zoom-europe').addEventListener('click',()=>focusRegion(-12,62,42,33));
 // La rueda solo hace zoom con Ctrl o en pantalla completa: sin eso, la página debe poder desplazarse.
 stage.addEventListener('wheel',event=>{if(!event.ctrlKey&&!watchMode())return;event.preventDefault();const [cx,cy]=mapPoint(event);zoomAt(event.deltaY<0?1.25:1/1.25,cx,cy);},{passive:false});
 stage.addEventListener('dblclick',event=>{if(event.target.closest('.map-zoom'))return;const [cx,cy]=mapPoint(event);zoomAt(1.8,cx,cy);});
 stage.addEventListener('pointerdown',event=>{if(event.button!==0||event.target.closest('.map-zoom')||zoomLevel()<1.02)return;const [x,y]=mapPoint(event);start={x,y,px:event.clientX,py:event.clientY};dragged=false;});
 window.addEventListener('pointermove',event=>{if(!start)return;if(Math.hypot(event.clientX-start.px,event.clientY-start.py)<4)return;dragged=true;const [x,y]=mapPoint(event);view.x+=start.x-x;view.y+=start.y-y;clampView();$('world-map').setAttribute('viewBox',`${view.x.toFixed(1)} ${view.y.toFixed(1)} ${view.w.toFixed(1)} ${view.h.toFixed(1)}`);});
 window.addEventListener('pointerup',()=>{if(start){start=null;setTimeout(()=>{dragged=false;},0);}});
})();
function render(){for(const [id,value] of Object.entries({'kpi-total':payload.total,'kpi-blocked':payload.blocked,'kpi-allowed':payload.allowed,'kpi-countries':payload.countries.length}))$(id).textContent=num(value);
$('kpi-period').textContent=payload.days===1?'Últimas 24 horas':`Últimos ${payload.days} días`;$('map-window').textContent=payload.days===1?'24 HORAS':payload.days+' DÍAS';
$('kpi-coverage').textContent=`${num(payload.located)} eventos geolocalizados`;
$('map-updated').textContent='Actualizado '+payload.generated_at+' · refresco cada 60 s';
$('geo-summary').textContent=`${num(payload.located)} geolocalizados · ${num(payload.private)} sin IP pública · ${num(payload.unknown_location)} ubicación desconocida · ${num(payload.pending)} pendientes`+(payload.limited?' · Volumen limitado a los 20.000 eventos más recientes.':'');
if(payload.geo_error)$('geo-summary').textContent+=' · '+payload.geo_error;
if(payload.history_pending)$('geo-summary').textContent+=' · Recuperación de los últimos 30 días en curso.';
if(payload.geo_database)$('geo-summary').textContent+=' · Base GeoIP: '+payload.geo_database;
const rank=$('country-ranking');rank.replaceChildren();const max=payload.countries[0]?.count||1;payload.countries.slice(0,12).forEach(c=>{const b=element('button',undefined,'country-row');b.type='button';const top=element('span',undefined,'country-top');top.append(element('span',c.name),element('strong',num(c.count)));const bar=element('span',undefined,'country-bar'),fill=element('i');fill.style.width=(c.count/max*100)+'%';bar.append(fill);b.append(top,bar);b.addEventListener('click',()=>choose(c.code));rank.append(b);});if(!payload.countries.length)rank.append(element('p','Sin países identificados en este periodo.','insight-hint'));
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
