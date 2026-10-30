# Historical v1 test: manual issuer flow. For v2 run viewer_and_flip.py instead.
import json,pathlib,urllib.request,urllib.error,hashlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
db=json.loads((root/'data/ledger.json').read_text(encoding='utf8'));d=max((d for d in db['deliveries'].values() if d['status']=='ready'),key=lambda d:d['issued_at']);a=db['assets'][d['asset_id']]
checks=[]
for prefix,record in [('media',d),('original',a)]:
    raw=pathlib.Path(record['path']).read_bytes();url='http://127.0.0.1:8769/'+prefix+'/'+record['id']
    for header,expected in [('bytes=0-1023',raw[:1024]),('bytes=1024-2047',raw[1024:2048]),('bytes=-512',raw[-512:]),('bytes=0-',raw)]:
        with urllib.request.urlopen(urllib.request.Request(url,headers={'Range':header}),timeout=10) as r:
            checks.append({'case':prefix+' '+header,'passed':r.status==206 and r.read()==expected,'content_range':r.headers.get('Content-Range')})
    with urllib.request.urlopen(url,timeout=10) as r: checks.append({'case':prefix+' full download','passed':r.status==200 and r.read()==raw})
    try:urllib.request.urlopen(urllib.request.Request(url,headers={'Range':'bytes='+str(len(raw)+100)+'-'}),timeout=10)
    except urllib.error.HTTPError as e:checks.append({'case':prefix+' invalid range','passed':e.code==416})
    else:checks.append({'case':prefix+' invalid range','passed':False})
config=json.loads((root/'config.json').read_text())
media=json.loads(subprocess.check_output([config['ffprobe'],'-v','error','-show_streams','-show_format','-of','json',d['path']],creationflags=0x08000000))
checks.append({'case':'Output audio present','passed':any(s['codec_type']=='audio' for s in media['streams'])})
checks.append({'case':'8-second output duration retained','passed':abs(float(media['format']['duration'])-8)<0.1})
checks.append({'case':'UI default strength 0.4','passed':d['processing']['strength']==0.4})
checks.append({'case':'UI-issued copy passes authentication','passed':d['processing']['saved_mp4_authenticated_match']})
(root/'tests/results/http_media.json').write_text(json.dumps(checks,indent=2),encoding='utf8')
print(json.dumps(checks,indent=2))
assert all(c['passed'] for c in checks)
