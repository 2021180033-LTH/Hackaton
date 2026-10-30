"""End-to-end viewer-bound issuance and orientation normalization.
Creator and two viewers use separate cookie jars; expected codes are never sent
to the detector. QA playback events are explicitly client-reported signals.
"""
import datetime, hashlib, http.cookiejar, json, pathlib, subprocess, time
import urllib.request, urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE='http://127.0.0.1:8769'
OUT=ROOT/'tests/results'/('viewer_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
OUT.mkdir()
EXPORT=ROOT.parent/'outputs/Forensic_G_시청자_반전_검증.json'
cfg=json.loads((ROOT/'config.json').read_text(encoding='utf8'))
class Client:
    def __init__(self,name):
        self.name=name;self.jar=http.cookiejar.CookieJar()
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
    def req(self,path,data=None,headers=None):
        h={'User-Agent':self.name,**(headers or {})}
        if data is not None:
            h['X-Forensic-G']='1';h['Content-Type']='application/octet-stream'
            if isinstance(data,dict):data=json.dumps(data).encode();h['Content-Type']='application/json'
        with self.opener.open(urllib.request.Request(path if path.startswith('http') else BASE+path,data=data,headers=h),timeout=30) as r:
            b=r.read();return json.loads(b) if 'application/json' in r.headers.get('Content-Type','') else b
    def cookie(self,name):return next((c.value for c in self.jar if c.name==name),None)
admin=Client('FG-Creator-QA');admin.req((ROOT/'data/admin_url.txt').read_text(encoding='utf8'))
viewers=[Client('FG-Viewer-A-QA'),Client('FG-Viewer-B-QA')]
result={'scope':'One 8s 720p synthetic source, two viewer sessions, strength 0.4; all transformed clips reencoded H.264 CRF23.',
        'checks':[],'transforms':[],'negative_controls':[],'complete':False,
        'engine_sha256':hashlib.sha256((ROOT/'ForensicEngine.dll').read_bytes()).hexdigest()}
def persist():
    text=json.dumps(result,ensure_ascii=False,indent=2)
    (OUT/'report.json').write_text(text,encoding='utf8');EXPORT.write_text(text,encoding='utf8')
def check(name,passed,**details):
    row={'name':name,'passed':bool(passed),**details};result['checks'].append(row);persist();print(name,bool(passed),flush=True)
    if not passed:raise AssertionError(row)
def denied(client,path,code=403,data=None,headers=None):
    try:client.req(path,data,headers)
    except urllib.error.HTTPError as e:return e.code==code
    return False
def wait():
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        s=admin.req('/api/state')
        if not s['busy']:
            if s['job']['status']=='error':raise RuntimeError(s['job']['message'])
            return s
        time.sleep(.5)
    raise TimeoutError('Job timeout')
def inspect(path):
    j=admin.req('/api/inspect',path.read_bytes());s=wait();return s['reports'][j['id']]
def convert(src,dst,vf):
    subprocess.run([cfg['ffmpeg'],'-v','error','-nostdin','-n','-i',str(src),'-vf',vf+',setsar=1',
                    '-c:v','libx264','-preset','medium','-crf','23','-pix_fmt','yuv420p',
                    '-c:a','aac','-map_metadata','-1',str(dst)],check=True,timeout=90,creationflags=0x08000000)

before=admin.req('/api/state');assert not before['busy']
asset=admin.req('/api/assets',(ROOT/'sample.mp4').read_bytes(),{'X-Filename':'viewer_flow_sample.mp4'})
check('Creator upload does not issue any viewer watermark',len(admin.req('/api/state')['deliveries'])==len(before['deliveries']))
check('Legacy creator-side issue API disabled',denied(admin,'/api/issue',410,{'asset_id':asset['id']}))
deliveries=[]
for i,viewer in enumerate(viewers):
    label='Viewer-'+('A' if i==0 else 'B')
    viewer.req('/watch/'+asset['id'])
    check(label+' cannot access creator ledger',denied(viewer,'/api/state'))
    check(label+' cannot fetch original',denied(viewer,'/original/'+asset['id']))
    pending=viewer.req('/api/playback/start',{'asset_id':asset['id'],'request_ip':'198.51.100.77','label':'FAKE CREATOR'}, {'X-Forwarded-For':'198.51.100.88'})
    state=wait();d=state['deliveries'][pending['id']]
    check(label+' copy verified',d['status']=='ready')
    check(label+' recorded viewer identity, not creator',d['issuance_context']=='viewer_playback' and d['viewer_browser_id']==viewer.cookie('fg_viewer') and d['user_agent']==viewer.name and d['label']!='FAKE CREATOR')
    check(label+' untrusted IP inputs ignored',d['viewer_request_ip']=='127.0.0.1')
    check(label+' no media transmission invented',not d.get('first_media_request_at') and not d['playback_events'])
    check(label+' event before media rejected',denied(viewer,'/api/playback/'+d['id']+'/events',409,{'event':'playing','position_seconds':0}))
    owned=viewer.req('/api/playback/'+d['id'])
    local=OUT/(label+'.mp4');local.write_bytes(viewer.req(owned['media_url']))
    event=viewer.req('/api/playback/'+d['id']+'/events',{'event':'playing','position_seconds':.2})
    check(label+' event explicitly marked client-reported',event['evidence_type']=='client_reported')
    d=admin.req('/api/state')['deliveries'][d['id']]
    check(label+' actual media request recorded',d['first_media_request_ip']=='127.0.0.1' and bool(d['accesses']))
    deliveries.append(d)
    check(label+' creator cannot fetch viewer stream',denied(admin,'/stream/'+d['id']))
    check(label+' legacy media URL cannot bypass session binding',denied(admin,'/media/'+d['id']))

check('Two viewers receive different browser/session/code IDs',deliveries[0]['viewer_browser_id']!=deliveries[1]['viewer_browser_id'] and deliveries[0]['playback_session_id']!=deliveries[1]['playback_session_id'] and deliveries[0]['id']!=deliveries[1]['id'])
for i in range(2):
    other=deliveries[1-i]['id'];check('Viewer cannot fetch other viewer stream '+str(i),denied(viewers[i],'/stream/'+other))
    check('Viewer cannot read other playback status '+str(i),denied(viewers[i],'/api/playback/'+other))

cases=[('identity','null','identity'),('horizontal','hflip','horizontal_flip'),('vertical','vflip','vertical_flip'),
       ('both','hflip,vflip','both_flips'),('horizontal_360p','hflip,scale=640:360','horizontal_flip'),
       ('vertical_stretch','vflip,scale=1920:720','vertical_flip'),
       ('horizontal_crop125','crop=1024:576:(iw-ow)/2:(ih-oh)/2,scale=1280:720,hflip','horizontal_flip'),
       ('horizontal_crop150','crop=854:480:(iw-ow)/2:(ih-oh)/2,scale=1280:720,hflip','horizontal_flip')]
for i,d in enumerate(deliveries):
    label='Viewer-'+('A' if i==0 else 'B');source=OUT/(label+'.mp4')
    for name,vf,direction in cases:
        target=OUT/(label+'_'+name+'.mp4');convert(source,target,vf);r=inspect(target)
        matched=r['status']=='matched' and r.get('delivery',{}).get('id')==d['id']
        row={'viewer':label,'case':name,'filter':vf,'matched_correct_viewer':matched,'status':r['status'],
             'orientation':r.get('channel_recovery',{}).get('orientation'),'expected_orientation':direction,
             'correction_bits':r.get('channel_recovery',{}).get('corrected_bits'),'detector_seconds':r['elapsed_seconds'],
             'expected_delivery_id':d['id'],'report_id':r['report_id'],'video_path':str(target)}
        result['transforms'].append(row);persist();print(label,name,r['status'],row['orientation'],flush=True)
        if r['status']=='matched':check(label+' '+name+' never attributes to wrong viewer',matched)
for name,vf in [('original','null'),('horizontal','hflip'),('vertical','vflip')]:
    target=OUT/('negative_'+name+'.mp4');convert(ROOT/'sample.mp4',target,vf);r=inspect(target)
    result['negative_controls'].append({'case':name,'status':r['status'],'passed':r['status']=='not_identified' and 'delivery' not in r})
    persist();print('Negative',name,r['status'],flush=True)
result['summary']={name:{'matched':sum(x['matched_correct_viewer'] for x in result['transforms'] if x['case']==name),'tested':2} for name,_,_ in cases}
result['complete']=True;persist();print('Viewer/flip test completed',flush=True)
