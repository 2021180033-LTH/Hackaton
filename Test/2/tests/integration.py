# Historical v1 test: manual issuer flow. For v2 run viewer_and_flip.py instead.
"""Real VideoSeal / FFmpeg / HTTP integration test; stdlib Python only for QA.
Run against an already-running localhost Forensic_G. Records are kept for the demo.
"""
import json, time, urllib.request, urllib.error, http.cookiejar, pathlib, subprocess, hashlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE='http://127.0.0.1:8769'
OUT=ROOT/'tests'/'results';OUT.mkdir(exist_ok=True)
FF=json.loads((ROOT/'config.json').read_text())['ffmpeg']
jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def req(path,data=None,headers=None):
    if isinstance(data,bytes): headers={'Content-Type':'application/octet-stream',**(headers or {})}
    if isinstance(data,dict): data=json.dumps(data).encode(); headers={**(headers or {}),'Content-Type':'application/json'}
    r=client.open(urllib.request.Request(BASE+path,data=data,headers={**({'X-Forensic-G':'1'} if data is not None else {}),**(headers or {})}),timeout=120)
    b=r.read()
    return json.loads(b) if 'application/json' in r.headers.get('Content-Type','') else b
def wait():
    deadline=time.time()+300
    while time.time()<deadline:
        s=req('/api/state')
        if not s['busy']:
            assert s['job']['status']!='error',s['job']
            return s
        time.sleep(1)
    raise TimeoutError('Job exceeded 300 seconds')
def inspect(path):
    j=req('/api/inspect',path.read_bytes());s=wait();return s['reports'][j['id']]
def ff(*args): subprocess.run([FF,'-v','error','-nostdin','-y',*map(str,args)],check=True,creationflags=0x08000000)
req('/')
sample=ROOT/'sample.mp4';before=hashlib.sha256(sample.read_bytes()).hexdigest()
asset=req('/api/assets',sample.read_bytes(),{'X-Filename':'sample.mp4'})
result={'asset_id':asset['id'],'checks':[],'deliveries':[],'reports':[]}
def check(name,passed,**extra):
    result['checks'].append({'name':name,'passed':bool(passed),**extra});print(name,passed,extra,flush=True)
for label in ['QA-A','QA-B']:
    d=req('/api/issue',{'asset_id':asset['id'],'label':label,'strength':0.2,'fps':24})
    s=wait();d=s['deliveries'][d['id']];result['deliveries'].append(d)
    check(label+' saved MP4 authenticated decode',d['status']=='ready',status=d['status'],seconds=d.get('processing',{}).get('elapsed_seconds'),raw_exact=d.get('processing',{}).get('saved_mp4_exact_match'),corrected_bits=d.get('processing',{}).get('channel_recovery',{}).get('corrected_bits'))
    if d['status']!='ready':
        (OUT/'integration.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8');raise RuntimeError('Saved MP4 validation failed')
    local=OUT/(label+'.mp4');local.write_bytes(req('/media/'+d['id']))
    report=inspect(local);result['reports'].append(report)
    check(label+' correct attribution',report['status']=='matched' and report['delivery']['id']==d['id'])
check('Unique delivery IDs',result['deliveries'][0]['id']!=result['deliveries'][1]['id'])
check('Same IP, separate deliveries',result['deliveries'][0]['request_ip']==result['deliveries'][1]['request_ip']=='127.0.0.1')
original=inspect(sample);result['reports'].append(original)
check('Unwatermarked original not attributed',original['status']=='not_identified' and 'delivery' not in original)
reencoded=OUT/'QA-A-reencoded.mp4'
ff('-i',OUT/'QA-A.mp4','-map_metadata','-1','-vf','scale=854:480','-c:v','libx264','-crf','23','-c:a','aac',reencoded)
rr=inspect(reencoded);result['reports'].append(rr)
check('480p CRF23 reencode attribution',rr['status']=='matched' and rr.get('delivery',{}).get('id')==result['deliveries'][0]['id'],status=rr['status'])
crop=OUT/'QA-A-trimmed.mp4'
ff('-ss','2','-i',OUT/'QA-A.mp4','-t','3','-map_metadata','-1','-c:v','libx264','-crf','23','-c:a','aac',crop)
cr=inspect(crop);result['reports'].append(cr)
check('3-second temporal excerpt attribution',cr['status']=='matched' and cr.get('delivery',{}).get('id')==result['deliveries'][0]['id'],status=cr['status'])
try:req('/api/assets',b'not a video')
except urllib.error.HTTPError as e:check('Invalid media rejected',e.code>=400)
else:check('Invalid media rejected',False)
try:client.open(urllib.request.Request(BASE+'/api/issue',data=b'{}',headers={'Origin':'https://example.org','X-Forensic-G':'1'}))
except urllib.error.HTTPError as e:check('Cross-origin mutation rejected',e.code==403)
else:check('Cross-origin mutation rejected',False)
check('Original file unchanged',hashlib.sha256(sample.read_bytes()).hexdigest()==before)
result['scope']='Two 8s synthetic cartoon videos at 720p/24fps, default strength 0.2, one original negative, 480p CRF23 reencode, 3-second temporal excerpt. No screen capture, collusion, adversarial removal or large-scale identity validation.'
(OUT/'integration.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
print('Saved',OUT/'integration.json',flush=True)
