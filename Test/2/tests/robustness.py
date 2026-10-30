# Historical v1 test: manual issuer flow. For v2 run viewer_and_flip.py instead.
"""Compare stronger watermark against observed resize/reencode failure at 0.2."""
import json,time,urllib.request,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1];OUT=ROOT/'tests/results';BASE='http://127.0.0.1:8769'
def req(path,data=None):
    h={}
    if data is not None:
        h={'X-Forensic-G':'1','Content-Type':'application/octet-stream'}
        if isinstance(data,dict):data=json.dumps(data).encode();h['Content-Type']='application/json'
    with urllib.request.urlopen(urllib.request.Request(BASE+path,data=data,headers=h),timeout=120) as r:
        b=r.read();return json.loads(b) if 'application/json' in r.headers.get('Content-Type','') else b
def wait():
    for _ in range(300):
        s=req('/api/state')
        if not s['busy']:
            assert s['job']['status']!='error',s['job'];return s
        time.sleep(1)
    raise TimeoutError()
def inspect(p):j=req('/api/inspect',p.read_bytes());return wait()['reports'][j['id']]
state=req('/api/state');aid=max(state['assets'].values(),key=lambda a:a['created_at'])['id'];ff=json.loads((ROOT/'config.json').read_text())['ffmpeg'];results=[]
for label in ['Strong-A','Strong-B']:
    d=req('/api/issue',{'asset_id':aid,'label':label,'strength':0.4,'fps':24});d=wait()['deliveries'][d['id']];assert d['status']=='ready',d
    p=OUT/(label+'.mp4');p.write_bytes(req('/media/'+d['id']))
    for change,args in [('480p_crf23',['-vf','scale=854:480','-crf','23']),('trim3s_crf23',['-ss','2','-t','3','-crf','23'])]:
        q=OUT/(label+'_'+change+'.mp4');subprocess.run([ff,'-v','error','-nostdin','-y','-i',str(p),*args,'-c:v','libx264','-c:a','aac','-map_metadata','-1',str(q)],check=True,creationflags=0x08000000)
        r=inspect(q);passed=r['status']=='matched' and r['delivery']['id']==d['id'];results.append({'case':label+' '+change,'passed':passed,'delivery':d,'report':r});print(label,change,passed,'corrected',r.get('channel_recovery'),flush=True)
(OUT/'robustness.json').write_text(json.dumps(results,indent=2,ensure_ascii=False),encoding='utf8')
print('All robustness cases:',all(r['passed'] for r in results),flush=True)
