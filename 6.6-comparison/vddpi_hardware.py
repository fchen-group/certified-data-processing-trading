#!/usr/bin/env python3
"""Real Gramine-SGX entry and independent TLS peer. Public fixtures only."""
import hashlib,json,math,os,shutil,socket,ssl,subprocess,time
from pathlib import Path

IMAGE=os.environ.get('VDDPI_RUNTIME_IMAGE', 'sha256:2565480e725baff099b3197fb8c07147899439aa69c9ad5ec492a0f95f7d3fbb')
DATA_ID='https://public-fixture/data/svm/shared'
CACHE=DATA_ID.replace('/','-')
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,x): Path(p).write_text(json.dumps(x,indent=2)+'\n')
def compare(x,y):
    assert set(x)==set(y),(x,y)
    for k in ('count','support_vectors','training_correct'):
        assert type(x[k]) is int and x[k]==y[k],(k,x,y)
    assert type(x['rho']) in (int,float) and math.isfinite(x['rho'])
    assert abs(x['rho']-y['rho'])<=1e-7*(1+abs(y['rho'])),(x,y)
def parse(p,key):
    found=[]
    for l in Path(p).read_text().splitlines():
        if l.startswith('{'):
            try: x=json.loads(l)
            except ValueError: continue
            if key in x: found.append(x)
    assert len(found)==1,(str(p),key,len(found))
    return found[0]

class Hardware:
    def __init__(self,root,out,app_folder="vddpi", math_mode=None):
        self.root=Path(root).resolve(); self.app=self.root/app_folder; self.out=Path(out).resolve()
        self.out.mkdir(parents=True,exist_ok=False)
        self.math_mode=math_mode
        self.cache=self.app/'sgx-data'/CACHE
        self.argv=['sudo','-n','docker','run','--rm','--network','host',
                   '--user',str(os.getuid())+':'+str(os.getgid()),
                   '--group-add',str(os.stat('/dev/sgx_enclave').st_gid),
                   '--group-add',str(os.stat('/dev/sgx_provision').st_gid),
                   '--device','/dev/sgx_enclave','--device','/dev/sgx_provision',
                   '-v','/var/run/aesmd:/var/run/aesmd',
                   '-v',str(self.app)+':/work','-w','/work','--entrypoint','/bin/bash',
                   IMAGE,'-lc','exec gramine-sgx benchmark']
    def launch(self,label,config):
        d=self.out/label; d.mkdir()
        if self.math_mode is not None: config=dict(config,math_probe_mode=self.math_mode)
        save(self.app/'config.json',config); save(d/'config.json',config)
        save(d/'command.json',dict(argv=self.argv,timeout_seconds=900))
        so=(d/'stdout.txt').open('wb'); se=(d/'stderr.txt').open('wb')
        p=subprocess.Popen(self.argv,stdout=so,stderr=se)
        return d,p,so,se,time.monotonic()
    def finish(self,job):
        d,p,so,se,start=job
        try: code=p.wait(timeout=max(1,900-(time.monotonic()-start)))
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(); raise
        finally: so.close(); se.close()
        save(d/'exit.json',dict(returncode=code,wall_seconds=time.monotonic()-start))
        return d,code
    def simple(self,label,config,key):
        d,code=self.finish(self.launch(label,dict(config,public_test_only=True)))
        assert code==0,(label,code,(d/'stderr.txt').read_text()[-3000:])
        return parse(d/'stdout.txt',key)
    def probe(self):
        x=self.simple('hardware-report',{'mode':'probe'},'local_report_hex')
        sig=json.loads((self.root/('control-signatures.json' if self.math_mode is None else 'signatures.json')).read_text())['benchmark']
        report=bytes.fromhex(x['local_report_hex'])
        assert len(report)==432 and report[64:96].hex()==sig['mrenclave']==x['mrenclave']
        assert int.from_bytes(report[48:56],'little')==x['flags'] and not x['flags']&2
        save(self.out/'hardware-acceptance.json',dict(status='passed',report=x,
             evidence='Hardware local REPORT matching signed measurement, not remote attestation'))
    def prepare(self,label,n,counter='2'):
        if self.cache.exists(): self.cache.unlink()
        raw=self.app/'input'/('adult-%s.csv'%n)
        c=dict(public_test_only=True,mode='prepare',data_id=DATA_ID,input='/input/'+raw.name,
               input_sha256=sha(raw),client_cn='test-consumer',
               condition=dict(counter=counter,expirationDate='',location=''))
        x=self.simple(label+'-prepare',c,'prepared')
        assert x==dict(prepared=True,input_sha256=c['input_sha256'])
        encrypted=self.cache.read_bytes()
        assert len(encrypted)>len(raw.read_bytes()) and raw.read_bytes()[:100] not in encrypted
        save(self.out/(label+'-cache-before.json'),dict(size=len(encrypted),sha256=sha(self.cache)))
        return c
    def execute(self,label,n,corrupt=False,wrong_app=False,counter='2'):
        c=self.prepare(label,n,counter)
        if corrupt:
            shutil.copy2(self.cache,self.out/(label+'-encrypted-original.bin'))
            damaged=bytearray(self.cache.read_bytes()); offset=min(5000,len(damaged)-1)
            damaged[offset]^=1; self.cache.write_bytes(damaged)
            shutil.copy2(self.cache,self.out/(label+'-encrypted-damaged.bin'))
            save(self.out/(label+'-corruption.json'),dict(byte_offset=offset,sha256=sha(self.cache)))
            diagnostic,code=self.finish(self.launch(label+'-direct-read',dict(c,mode='inspect')))
            error_log=(diagnostic/'stdout.txt').read_text()+(diagnostic/'stderr.txt').read_text()
            assert code==1 and 'PermissionError' in error_log and 'Permission denied' in error_log
        # Warm the physical encrypted-file cache, outside the enclave timer.
        self.cache.read_bytes()
        token=self.root/('wrong-app.txt' if wrong_app else 'tokens.txt')
        shutil.copy2(token,self.app/'tokens.txt')
        listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1); listener.settimeout(90)
        c.update(mode='run',tokens='tokens.txt',peer_host='127.0.0.1',peer_port=listener.getsockname()[1])
        job=self.launch(label,c); received=b''; error=None
        try:
            conn,_=listener.accept(); conn.settimeout(800)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cafile=str(self.app/'fixtures/RootCA.pem'))
            ctx.load_cert_chain(str(self.app/'fixtures/client.pem'),str(self.app/'fixtures/client.key'))
            with ctx.wrap_socket(conn,server_hostname='vddpi-test') as peer:
                while True:
                    part=peer.recv(65536)
                    if not part: break
                    received+=part
                    if len(received)>4096: raise ValueError('unexpected result length')
        except Exception as e: error=repr(e)
        finally: listener.close()
        d,code=self.finish(job); (d/'received.json').write_bytes(received)
        save(d/'peer.json',dict(error=error,received_bytes=len(received)))
        if corrupt or wrong_app:
            assert code!=0 and not received,(label,code,received)
            error_log=(d/'stdout.txt').read_text()+(d/'stderr.txt').read_text()
            if wrong_app: assert 'Invalid App' in error_log
            else:
                # Gramine stat() also denies corrupted encrypted files, so the
                # original service attempts acquisition, which fails closed.
                assert 'failed to receive authorized input' in error_log or 'PermissionError' in error_log,error_log
            return dict(name=label,rejected=True)
        assert code==0 and error is None,(label,code,error,(d/'stderr.txt').read_text()[-3000:])
        actual=json.loads(received); compare(actual,json.loads((self.root/'baseline/reference'/('expected-%s.json'%n)).read_text()))
        stats=parse(d/'stdout.txt','processing_ns')
        assert stats['cached'] and stats['network_send_after_endpoint']
        assert stats['begin_ns']<=stats['input_done_ns']<=stats['protected_done_ns']<=stats['cleanup_done_ns']
        assert stats['processing_ns']==stats['protected_done_ns']-stats['begin_ns']>0
        assert stats['protected_bytes']>len(received)==stats['plaintext_bytes']
        if counter=='1': assert not self.cache.exists()
        else:
            x=self.simple(label+'-inspect',dict(c,mode='inspect'),'condition')
            assert x['condition']['counter']==str(int(counter)-1) and x['input_sha256']==c['input_sha256'] and x['client_cn']=='test-consumer'
            save(d/'cache-after.json',dict(sha256=sha(self.cache),size=self.cache.stat().st_size,inspection=x))
        return dict(name=label,system='vddpi',n=n,processing_ms=stats['processing_ns']/1e6,
                    result=actual,validated=True,records_sha256=c['input_sha256'],phases_ns=stats)
