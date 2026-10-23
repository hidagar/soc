#!/usr/bin/env python3
"""Small stdlib-only UDP -> authenticated HTTPS relay with a bounded disk spool."""
import argparse,hashlib,json,os,socket,sqlite3,threading,time,uuid
from pathlib import Path
from contextlib import closing,contextmanager
from urllib.request import Request,build_opener,HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):return None

@contextmanager
def database(path):
    with closing(sqlite3.connect(path,timeout=15)) as db:
        with db:yield db

def counter(db,name,amount=1):
    db.execute('INSERT INTO counters VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value',(name,amount))

def durable_ack(status,reply,batch_id,lines):
    digest=hashlib.sha256(json.dumps(lines,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    return (status==202 and reply.get('persisted') is True and reply.get('batch_id')==batch_id
        and reply.get('digest')==digest and reply.get('accepted')==len(lines))

QUEUE_LIMIT=64*1024*1024
SIZE_REFRESH=10  # segundos entre recuentos exactos de la cola

def queue_bytes(db):
    return db.execute('SELECT (SELECT COALESCE(SUM(length(CAST(content AS BLOB))),0) FROM spool) + (SELECT COALESCE(SUM(length(CAST(content AS BLOB))),0) FROM batches)').fetchone()[0]

def spool_status(path):
    with database(path) as db:
        result=dict(db.execute('SELECT name,value FROM counters'))
        result['pending_messages']=db.execute('SELECT count(*) FROM spool').fetchone()[0]
        result['pending_batches']=db.execute('SELECT count(*) FROM batches').fetchone()[0]
        first=db.execute('SELECT min(created) FROM (SELECT created FROM spool UNION ALL SELECT created FROM batches)').fetchone()[0]
        result['oldest_pending_seconds']=max(0,int(time.time()-first)) if first else 0
        return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--status',action='store_true');args=parser.parse_args()
    os.umask(0o077)
    config=json.loads(Path(args.config).read_text(encoding='utf-8'))
    if not config['url'].startswith('https://'):raise SystemExit('HTTPS required')
    spool=Path(config['spool']);spool.parent.mkdir(parents=True,exist_ok=True)
    with database(spool) as db:
        db.execute('CREATE TABLE IF NOT EXISTS spool (id TEXT PRIMARY KEY, content TEXT NOT NULL, created REAL NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS batches (id TEXT PRIMARY KEY, content TEXT NOT NULL, created REAL NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)')
    if args.status:
        print(json.dumps(spool_status(spool)));return
    def forward():
        opener=build_opener(NoRedirect())
        while True:
            try:
                with database(spool) as db:
                    # Never expire unacknowledged data. Capacity bounds new intake.
                    row=db.execute('SELECT id,content FROM batches ORDER BY created,id LIMIT 1').fetchone()
                    if not row:
                        selected=[];size=0
                        for candidate in db.execute('SELECT id,content FROM spool ORDER BY created,id LIMIT 32').fetchall():
                            length=len(json.dumps(candidate[1],ensure_ascii=False).encode('utf-8'))
                            if selected and size+length>96000:break
                            selected.append(candidate);size+=length
                        if selected:
                            batch_id=str(uuid.uuid4());content=json.dumps([r[1] for r in selected],ensure_ascii=False)
                            db.execute('INSERT INTO batches VALUES (?,?,?)',(batch_id,content,time.time()))
                            db.executemany('DELETE FROM spool WHERE id=?',[(r[0],) for r in selected]);row=(batch_id,content)
                if not row:time.sleep(1);continue
                lines=json.loads(row[1]);body=json.dumps({'batch_id':row[0],'messages':lines},ensure_ascii=False).encode()
                request=Request(config['url'],data=body,headers={'Authorization':'Bearer '+config['token'],'Content-Type':'application/json'},method='POST')
                with opener.open(request,timeout=20) as response:
                    reply=json.loads(response.read(4096))
                    if not durable_ack(response.status,reply,row[0],lines):raise ValueError('Durable storage not acknowledged')
                with database(spool) as db:
                    db.execute('DELETE FROM batches WHERE id=?',(row[0],))
                    counter(db,'persisted_messages',len(lines))
            except Exception:
                # Never log credentials, URLs with secrets, raw messages or exceptions.
                try:
                    with database(spool) as db:counter(db,'delivery_errors')
                except Exception:
                    pass  # Un fallo al contar no debe matar el hilo de entrega.
                print('Entrega pendiente; se conserva la cola local.',flush=True);time.sleep(15)
    forwarder=threading.Thread(target=forward,daemon=True);forwarder.start()
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as listener:
        try:listener.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)  # ráfagas sin pérdidas silenciosas
        except OSError:pass
        listener.bind((config.get('listen_host','127.0.0.1'),int(config.get('listen_port',5515))))
        listener.settimeout(5)
        print('Reenviador iniciado. Revisa el portal para confirmar la interpretación en Wazuh.',flush=True)
        # Tamaño de la cola: recuento exacto cada SIZE_REFRESH s y suma de lo recibido entre medias.
        # Antes se sumaba toda la cola por cada mensaje, lo que frenaba la recepción justo durante un corte.
        queued,counted_at=0,0.0
        while True:
            if not forwarder.is_alive():
                # Sin hilo de entrega el servicio parecería activo sin reenviar nada: salir para que systemd lo reinicie.
                raise SystemExit('El hilo de entrega se ha detenido; reinicio del servicio.')
            try:content,_=listener.recvfrom(8193)
            except socket.timeout:continue
            if len(content)>8192:
                with database(spool) as db:counter(db,'invalid_messages')
                continue
            try:line=content.decode('utf-8').rstrip('\r\n')
            except UnicodeError:
                with database(spool) as db:counter(db,'invalid_messages')
                continue
            if not line or any(ord(c)<32 and c!='\t' for c in line) or '\x7f' in line:
                with database(spool) as db:counter(db,'invalid_messages')
                continue
            with database(spool) as db:
                if time.monotonic()-counted_at>=SIZE_REFRESH:
                    queued,counted_at=queue_bytes(db),time.monotonic()
                length=len(json.dumps(line,ensure_ascii=False).encode())
                if queued+length>QUEUE_LIMIT:
                    counter(db,'overflow_dropped')
                    print('Cola local llena; se descarta el nuevo mensaje. Revisar conectividad.',flush=True);continue
                db.execute('INSERT INTO spool VALUES (?,?,?)',(str(uuid.uuid4()),line,time.time()))
                counter(db,'received_messages')
                queued+=length

if __name__=='__main__':main()
