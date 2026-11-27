from pathlib import Path
import json,subprocess,hashlib,re,sys,datetime
root=Path('/Users/bytedance/project-z/netz');old=Path('/Users/bytedance/project-z/.netz-writer-storage-baseline-a9b');outdir=Path('/tmp/netz-writer-resource-logs');outdir.mkdir(exist_ok=True)
bins={'baseline':old/'zig-out/bin/netz-proxy-target-writer-probe','candidate':root/'zig-out/bin/netz-proxy-target-writer-probe'};result={'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_baseline':'a9b8555795088072bc2858f60e77359ececd4e3f','binary_sha256':{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in bins.items()},'rows':[],'scope':'controlled target-write stalls, actual10ms deadlines, real distinct TCP sockets; service/retained-memory measurement, not kernel pressure or full proxy throughput'}
for backend in ['application','threaded']:
 for count in [1,8,32]:
  for burst in [False,True]:
   for label in ['baseline','candidate']:
    args=[str(bins[label]),'--count='+str(count)]+(['--threaded'] if backend=='threaded' else [])+(['--burst'] if burst else [])
    command=['/usr/bin/time','-l',*args];r=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);raw=r.stdout;log=outdir/f'{label}-{backend}-{count}-{int(burst)}.log';log.write_bytes(raw)
    receipt={'label':label,'backend':backend,'count':count,'burst':burst,'command':command,'exit_code':r.returncode,'log_sha256':hashlib.sha256(raw).hexdigest()}
    if r.returncode:
     result['rows'].append(receipt);Path('/tmp/netz-writer-resource-matrix.json').write_text(json.dumps(result,indent=2)+'\n');print(raw.decode(errors='replace'),flush=True);sys.exit(r.returncode)
    decoded=raw.decode();line=next(x for x in decoded.splitlines() if x.startswith('{'));data=json.loads(line);assert data['persistent']==(label=='candidate') and data['calls']==[count]*5 and data['zero_live_after_cleanup']
    rss=int(re.search(r'^\s*(\d+)\s+maximum resident set size\s*$',decoded,re.M).group(1));receipt['result']=data;receipt['maximum_rss_bytes']=rss;result['rows'].append(receipt);Path('/tmp/netz-writer-resource-matrix.json').write_text(json.dumps(result,indent=2)+'\n')
    print(label+' '+backend+' n='+str(count)+' burst='+str(burst)+' median_ms='+str(data['median_ns']/1e6)+' retained='+str(data['proxy_live_bytes'])+' rss='+str(rss),flush=True)
