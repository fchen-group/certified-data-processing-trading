#!/usr/bin/env python3
"""Generate, run and independently validate fixed-record-length commitment sweeps."""
import argparse
import base64
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = b"work2-commitment-length-v1:"
METRICS = ("salt_prepare_ns", "snapshot_ns", "preparation_ns")

def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""): h.update(b)
    return h.hexdigest()

def dump(path, value):
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+"\n")

def record(i, length):
    # Nested byte prefixes across lengths; deterministic public fixtures, not salts.
    return hashlib.shake_256(DOMAIN+i.to_bytes(8,"big")).hexdigest((length+1)//2)[:length].encode("ascii")

def check_config(c):
    assert c["stage"] in ("local-preexperiment","linux-client-preexperiment","linux-client-formal")
    for k in ("records","record_lengths"):
        assert c[k] and c[k] == sorted(set(c[k])) and all(type(x) is int and x>0 for x in c[k])
    assert c["repetitions"]>0 and c["gomaxprocs"]>0 and type(c["order_seed"]) is int
    assert c["input_generator"]=="shake256-hex-prefix-v1" and c["go_version"]=="go1.26.1"
    if c["stage"]=="linux-client-formal": assert c["repetitions"]==30

def prepare(cfg, out):
    check_config(cfg); out.mkdir(parents=True,exist_ok=False)
    outputs=[]
    for length in cfg["record_lengths"]:
        name=f"records-{length}.txt"; h=hashlib.sha256(); prefixes={}
        with (out/name).open("wb") as f:
            for i in range(1,max(cfg["records"])+1):
                row=record(i,length); f.write(row+b"\n"); h.update(row)
                if i in cfg["records"]: prefixes[str(i)]=h.hexdigest()
        outputs.append({"file":name,"length":length,"records":max(cfg["records"]),
            "file_bytes":(length+1)*max(cfg["records"]),"file_sha256":sha(out/name),"prefix_record_sha256":prefixes})
    dump(out/"manifest.json",{"generator":cfg["input_generator"],"generator_domain":DOMAIN.decode(),
        "length_definition":"raw record bytes; newline, salt and commitment encoding excluded", "outputs":outputs})

def orders(count, repetitions, seed):
    rng=random.Random(seed); result=[]
    while len(result)<repetitions:
        base=list(range(count));rng.shuffle(base)
        shifts=list(range(count));rng.shuffle(shifts)
        result.extend(base[s:]+base[:s] for s in shifts[:repetitions-len(result)])
    return result

def encode(*fields):
    return b"".join(len(f).to_bytes(8,"big")+f for f in fields)

def proof_root(n, index, leaf, siblings):
    it=iter(siblings)
    def walk(size, pos):
        if size==1: return leaf
        k=1<<((size-1).bit_length()-1)
        if pos<k: left=walk(k,pos);right=next(it)
        else: right=walk(size-k,pos-k);left=next(it)
        return hashlib.sha256(b"\x01"+left+right).digest()
    root=walk(n,index-1)
    assert next(it,None) is None
    return hashlib.sha256(b"\x02"+encode(n.to_bytes(8,"big"),root)).digest()

def check_measurement(r,n,length,cfg,entry):
    assert (r["schema"],r["n"],r["record_length"],r["record_bytes"])==("commitment-length-v1",n,length,n*length)
    assert r["go_version"]==cfg["go_version"] and r["gomaxprocs"]==cfg["gomaxprocs"]
    if cfg["stage"].startswith("linux-client-"): assert (r["os"],r["arch"])==("linux","amd64")
    assert r["record_sha256"]==entry["prefix_record_sha256"][str(n)]
    assert set(r["checks"])=={"reconstructed_commitment","proofs_verified","tampered_record_rejected"}
    assert all(v is True for v in r["checks"].values())
    assert all(type(r[k]) is int and r[k]>0 for k in METRICS)
    assert r["preparation_ns"]==r["salt_prepare_ns"]+r["snapshot_ns"]
    indices=sorted(set([1,n//2+1,n]))
    assert r["indices"]==indices and len(r["samples"])==len(indices)
    for i,s in zip(indices,r["samples"]):
        assert s["index"]==i
        raw=base64.b64decode(s["record"],validate=True)
        assert raw==record(i,length)
        salt=bytes.fromhex(s["salt"][2:]);assert len(salt)==32
        leaf=hashlib.sha256(b"\0"+encode(i.to_bytes(8,"big"),raw,salt)).digest()
        siblings=[bytes.fromhex(x[2:]) for x in s["proof"]["siblings"] or []]
        assert all(len(x)==32 for x in siblings)
        assert proof_root(n,i,leaf,siblings).hex()==r["commitment"][2:]

def summaries(raw):
    groups=defaultdict(list)
    for e in raw: groups[(e["n"],e["record_length"])].append(e["measurement"])
    out=[]
    for (n,l),rs in sorted(groups.items()):
        row={"n":n,"record_length":l,"repetitions":len(rs)}
        for k in METRICS:
            values=[r[k] for r in rs]
            row[k+"_mean"]=statistics.mean(values)
            row[k+"_stdev"]=statistics.stdev(values) if len(values)>1 else 0.0
        out.append(row)
    return out

def validate(out):
    cfg=json.loads((out/"config.json").read_text());check_config(cfg)
    manifest=json.loads((out/"manifest.json").read_text())
    dm=json.loads((out/"data-manifest.json").read_text()); bylen={e["length"]:e for e in dm["outputs"]}
    assert manifest["status"]=="complete"
    for name,key in [("config.json","config_sha256"),("data-manifest.json","data_manifest_sha256"),("source.tar.gz","source_archive_sha256")]:
        assert sha(out/name)==manifest[key]
    with tarfile.open(out/"source.tar.gz") as t:
        assert {m.name:hashlib.sha256(t.extractfile(m).read()).hexdigest() for m in t.getmembers() if m.isfile()}==manifest["source_sha256"]
    grid=[(n,l) for n in cfg["records"] for l in cfg["record_lengths"]]
    order=orders(len(grid),cfg["repetitions"],cfg["order_seed"])
    assert manifest["case_orders"]==order
    raw=[json.loads(s) for s in (out/"raw.jsonl").read_text().splitlines()]
    assert len(raw)==len(grid)*cfg["repetitions"]==manifest["successful_processes"]
    roots=set(); salts=set()
    for k,e in enumerate(raw):
        rep,pos=divmod(k,len(grid)); n,l=grid[order[rep][pos]]
        assert (e["repetition"],e["position"],e["n"],e["record_length"],e["returncode"])==(rep+1,pos+1,n,l,0)
        r=e["measurement"];check_measurement(r,n,l,cfg,bylen[l])
        assert r["commitment"] not in roots;roots.add(r["commitment"])
        for sample in r["samples"]:
            assert sample["salt"] not in salts;salts.add(sample["salt"])
    recomputed=summaries(raw)
    with (out/"summary.csv").open() as f: saved=list(csv.DictReader(f))
    assert len(saved)==len(recomputed)
    for a,b in zip(saved,recomputed):
        for k,v in b.items(): assert math.isclose(float(a[k]),v,rel_tol=1e-12,abs_tol=1e-6)
    variability=[]
    for row in recomputed:
        values=[e["measurement"]["preparation_ns"]/1e6 for e in raw if (e["n"],e["record_length"])==(row["n"],row["record_length"])]
        variability.append({"n":row["n"],"record_length":row["record_length"],"mean_ms":statistics.mean(values),
            "stdev_ms":statistics.stdev(values) if len(values)>1 else 0,"min_ms":min(values),"median_ms":statistics.median(values),"max_ms":max(values),
            "cv":row["preparation_ns_stdev"]/row["preparation_ns_mean"],
            "block_means_ms":[statistics.mean(values[i:i+10]) for i in range(0,len(values),10)]})
    return {"observations":len(raw),"configurations":len(grid),"independent_proofs":sum(len(e["measurement"]["samples"]) for e in raw),
        "coverage_order_hashes_summaries_verified":True,"all_observations_retained":True,"groups":variability}

def run(config_path,inputs,out):
    cfg=json.loads(config_path.read_text());check_config(cfg)
    if cfg["stage"].startswith("linux-client-"): assert platform.system()=="Linux" and platform.machine()=="x86_64"
    dm=json.loads((inputs/"manifest.json").read_text());bylen={e["length"]:e for e in dm["outputs"]}
    assert dm["generator"]==cfg["input_generator"] and set(bylen)==set(cfg["record_lengths"])
    for entry in bylen.values():
        assert sha(inputs/entry["file"])==entry["file_sha256"]
        assert (inputs/entry["file"]).stat().st_size==entry["file_bytes"]
    out.mkdir(parents=True,exist_ok=False)
    shutil.copy2(config_path,out/"config.json");shutil.copy2(inputs/"manifest.json",out/"data-manifest.json")
    env=dict(os.environ,GOTOOLCHAIN=cfg["go_version"],GOWORK="off",GOFLAGS="",GOMAXPROCS=str(cfg["gomaxprocs"]),
        GOGC=str(cfg["gogc"]),GOMEMLIMIT=cfg["gomemlimit"],GODEBUG="")
    grid=[(n,l) for n in cfg["records"] for l in cfg["record_lengths"]]
    order=orders(len(grid),cfg["repetitions"],cfg["order_seed"])
    m={"status":"running","started_utc":datetime.now(timezone.utc).isoformat(),"host":platform.platform(),
       "machine":platform.machine(),"logical_cpus":os.cpu_count(),"case_orders":order,"config_sha256":sha(out/"config.json"),
       "data_manifest_sha256":sha(out/"data-manifest.json"),"runtime_environment":{k:env[k] for k in ["GOTOOLCHAIN","GOMAXPROCS","GOGC","GOMEMLIMIT","GODEBUG"]}}
    if platform.system()=="Linux":
        m["cpu_models"]=sorted({s.split(":",1)[1].strip() for s in Path("/proc/cpuinfo").read_text().splitlines() if s.startswith("model name")})
        m["os_release"]=Path("/etc/os-release").read_text();m["meminfo_before"]=Path("/proc/meminfo").read_text();m["load_before"]=os.getloadavg()
    raw=[]
    try:
        with tempfile.TemporaryDirectory(prefix="commitment-length-",dir=ROOT/"tmp") as tmp:
            stage=Path(tmp); hashes={}
            sources=[ROOT/"go.mod",ROOT/"go.sum",Path(__file__),config_path,*sorted((ROOT/"pkg/protocol").glob("*.go")),*sorted((ROOT/"6.3-certification/commitmentbench").glob("*.go"))]
            with tarfile.open(out/"source.tar.gz","w:gz") as t:
                for src in sorted(set(sources)):
                    rel=src.relative_to(ROOT);dest=stage/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
                    hashes[str(rel)]=sha(dest);t.add(dest,arcname=str(rel))
            m["source_sha256"]=hashes;m["source_archive_sha256"]=sha(out/"source.tar.gz")
            m["go"]=subprocess.check_output(["go","version"],env=env,text=True).strip()
            assert cfg["go_version"] in m["go"]
            binary=stage/"commitmentbench"
            cmd=["go","build","-mod=readonly","-trimpath","-buildvcs=false","-ldflags=-buildid=","-o",str(binary),"./6.3-certification/commitmentbench"]
            with (out/"build.log").open("w") as f:subprocess.run(cmd,cwd=stage,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
            m["build_command"]=cmd[:-2]+["<temporary-binary>",cmd[-1]];m["binary_sha256"]=sha(binary)
            dump(out/"manifest.json",m)
            with (out/"raw.jsonl").open("w") as f:
                for rep,seq in enumerate(order,1):
                    for pos,k in enumerate(seq,1):
                        n,l=grid[k];entry=bylen[l]
                        e={"repetition":rep,"position":pos,"n":n,"record_length":l}
                        cmd=[str(binary),"-input",str(inputs/entry["file"]),"-n",str(n),"-length",str(l)]
                        try:
                            proc=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=cfg["process_timeout_seconds"])
                            e["returncode"]=proc.returncode;e["stderr"]=proc.stderr
                            if proc.returncode: e["stdout"]=proc.stdout;raise RuntimeError("measurement process failed")
                            e["measurement"]=json.loads(proc.stdout)
                            check_measurement(e["measurement"],n,l,cfg,entry)
                        except Exception as exc:
                            e["failure"]=str(exc);f.write(json.dumps(e)+"\n");f.flush();raise
                        f.write(json.dumps(e,separators=(",",":"))+"\n");f.flush();raw.append(e)
                    print(f"completed {rep}/{cfg['repetitions']}",flush=True)
            rows=summaries(raw)
            with (out/"summary.csv").open("w",newline="") as f:
                w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
            m["status"]="complete";m["successful_processes"]=len(raw)
    except Exception as exc:
        m["status"]="failed";m["failure"]=str(exc);raise
    finally:
        m["ended_utc"]=datetime.now(timezone.utc).isoformat();dump(out/"manifest.json",m)
    dump(out/"analysis.json",validate(out))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("action",choices=["prepare","run","validate"])
    p.add_argument("--config",type=Path);p.add_argument("--inputs",type=Path);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if a.action=="validate": print(json.dumps(validate(a.out),indent=2))
    elif a.action=="prepare": prepare(json.loads(a.config.read_text()),a.out)
    else: run(a.config.resolve(),a.inputs.resolve(),a.out.resolve())

if __name__=="__main__":main()
