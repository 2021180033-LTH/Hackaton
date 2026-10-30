"""Real video tests. Expected IDs stay in QA, never go to the decoder.
The engine receives only evidence and optional unwatermarked source references.
Uses the running local admin server; creates synthetic assets and viewer copies.
"""
import datetime, hashlib, http.cookiejar, json, pathlib, subprocess, time, urllib.request, urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE='http://127.0.0.1:8769'
OUT=ROOT/'tests/results'/('robust_v3_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S'));OUT.mkdir()
EXPORT=ROOT.parent/'outputs/Forensic_G_변형식별_v3_검증.json'
cfg=json.loads((ROOT/'config.json').read_text(encoding='utf8'))
class Client:
    def __init__(self,name):
        self.jar=http.cookiejar.CookieJar();self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar));self.name=name
    def req(self,path,data=None,headers=None):
        h={'User-Agent':self.name,**(headers or {})}
        if data is not None:
            h['X-Forensic-G']='1';h.setdefault('Content-Type','application/octet-stream')
            if isinstance(data,dict):data=json.dumps(data).encode();h['Content-Type']='application/json'
        with self.opener.open(urllib.request.Request(path if path.startswith('http') else BASE+path,data=data,headers=h),timeout=60) as r:
            b=r.read();return json.loads(b) if 'application/json' in r.headers.get('Content-Type','') else b
admin=Client('FG-Robustness-QA');admin.req((ROOT/'data/admin_url.txt').read_text(encoding='utf8'))
result={'version':'3','strength':cfg.get('watermark_strength',0.4),'scope':'Two synthetic 8-second 720p sources; 3 distinct viewer codes; transformed files H264 CRF23. Not a general robustness guarantee.',
        'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'cases':[],'negative_controls':[],'checks':[],'complete':False,
        'engine_sha256':hashlib.sha256((ROOT/'ForensicEngine.dll').read_bytes()).hexdigest()}
def persist():
    s=json.dumps(result,ensure_ascii=False,indent=2);(OUT/'report.json').write_text(s,encoding='utf8');EXPORT.write_text(s,encoding='utf8')
def wait():
    deadline=time.monotonic()+300
    while time.monotonic()<deadline:
        state=admin.req('/api/state')
        if not state['busy']:
            if state['job']['status']=='error':raise RuntimeError(state['job']['message'])
            return state
        time.sleep(.4)
    raise TimeoutError('Job timeout')
def inspect(path,ref='auto'):
    j=admin.req('/api/inspect',path.read_bytes(),{'X-Reference-Asset':ref});return wait()['reports'][j['id']]
def convert(src,dst,vf):
    subprocess.run([cfg['ffmpeg'],'-v','error','-nostdin','-n','-i',str(src),'-vf',vf+',setsar=1','-c:v','libx264','-preset','medium','-crf','23','-pix_fmt','yuv420p','-c:a','aac','-map_metadata','-1',str(dst)],check=True,timeout=120,creationflags=0x08000000)
cases=[('reencode','null'),('upscale_1080','scale=1920:1080'),('downscale_360','scale=640:360'),('downscale_180','scale=320:180'),
       ('stretch_wide','scale=1920:720'),('stretch_tall','scale=1280:1080'),('horizontal','hflip'),('vertical','vflip'),('both','hflip,vflip'),
       ('crop_150','crop=854:480:(iw-ow)/2:(ih-oh)/2,scale=1280:720'),
       ('crop_200','crop=640:360:(iw-ow)/2:(ih-oh)/2,scale=1280:720'),
       ('offcenter_crop150','crop=854:480:80:40,scale=1280:720'),
       ('crop150_flip_360','crop=854:480:(iw-ow)/2:(ih-oh)/2,hflip,scale=640:360'),
       ('shrink_pad_flip','scale=960:540,pad=1280:720:160:90:black,vflip'),
       ('extreme_crop400','crop=320:180:(iw-ow)/2:(ih-oh)/2,scale=1280:720,hflip')]
testsrc=OUT/'testsrc2.mp4'
subprocess.run([cfg['ffmpeg'],'-v','error','-nostdin','-n','-f','lavfi','-i','testsrc2=size=1280x720:rate=24','-t','8','-c:v','libx264','-preset','veryfast','-crf','18','-pix_fmt','yuv420p',str(testsrc)],check=True,creationflags=0x08000000)
assert not admin.req('/api/state')['busy']
for source_name,source,count in [('robot',ROOT/'sample.mp4',2),('pattern',testsrc,1)]:
    asset=admin.req('/api/assets',source.read_bytes(),{'X-Filename':source_name+'_v3.mp4'})
    for copy in range(count):
        viewer=Client(f'FG-{source_name}-{copy}-Viewer');viewer.req('/watch/'+asset['id'])
        pending=viewer.req('/api/playback/start',{'asset_id':asset['id']});d=wait()['deliveries'][pending['id']]
        assert d['status']=='ready' and d['payload_format']=='bch255_131_hmac64_v3'
        stream=viewer.req('/api/playback/'+d['id'])['media_url'];original=OUT/f'{source_name}_{copy}.mp4';original.write_bytes(viewer.req(stream))
        print('Issued',source_name,copy,d['id'],flush=True)
        for name,vf in cases:
            target=OUT/f'{source_name}_{copy}_{name}.mp4';convert(original,target,vf);r=inspect(target,asset['id']);decoded=r.get('delivery',{}).get('id')
            row={'source':source_name,'copy':copy,'case':name,'filter':vf,'expected_id':d['id'],'decoded_id':decoded,
                 'matched':r['status']=='matched' and decoded==d['id'],'status':r['status'],'report_id':r['report_id'],
                 'corrected_bits':r['channel_recovery'].get('corrected_bits'),'format':r['channel_recovery'].get('format'),
                 'geometry':r['channel_recovery'].get('geometry'),'geometry_attempted':r.get('geometry_fallback_used',False),
                 'registration_attempts':r.get('registration_attempts',[]),'seconds':r['elapsed_seconds'],'file':str(target)}
            result['cases'].append(row);persist();print(source_name,copy,name,r['status'],row['corrected_bits'],row['geometry'],flush=True)
            assert r['status']!='matched' or decoded==d['id'],'WRONG ID ATTRIBUTION'
    for name,vf in [('plain','null'),('crop_flip','crop=854:480:80:40,hflip,scale=1280:720')]:
        target=OUT/f'negative_{source_name}_{name}.mp4';convert(source,target,vf);r=inspect(target,asset['id'])
        passed=r['status']=='not_identified' and 'delivery' not in r
        result['negative_controls'].append({'source':source_name,'case':name,'status':r['status'],'passed':passed,'geometry_attempted':r.get('geometry_fallback_used',False)})
        persist();print('Negative',source_name,name,r['status'],flush=True);assert passed
# Backwards compatibility: old issued code, including an old flipped copy.
for name in ['Viewer-A_horizontal.mp4','Viewer-B_vertical.mp4']:
    p=ROOT/'tests/results/viewer_20261031_042210'/name;r=inspect(p,'none')
    passed=r['status']=='matched' and not r['channel_recovery'].get('format')
    result['checks'].append({'name':'Legacy code '+name,'passed':passed});assert passed
result['summary']={name:{'matched':sum(c['matched'] for c in result['cases'] if c['case']==name),'tested':sum(c['case']==name for c in result['cases'])} for name,_ in cases}
result['complete']=True;persist();print('COMPLETE',json.dumps(result['summary']),flush=True)
