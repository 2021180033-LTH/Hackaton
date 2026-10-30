"""Black-box evaluation of the existing executable; does not modify embed/detect code.

The expected watermark is used only AFTER the HTTP detector returns, for scoring.
All geometries include H.264 CRF23 re-encoding, no preservation in MP4 metadata.
"""
import datetime
import hashlib
import http.cookiejar
import json
import pathlib
import subprocess
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:8769'
STAMP = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
OUT = ROOT / 'tests' / 'results' / ('geometry_' + STAMP)
OUT.mkdir()
EXPORT = ROOT.parent / 'outputs' / 'Forensic_G_크기변형_검증.json'
CFG = json.loads((ROOT / 'config.json').read_text(encoding='utf8'))

CASES = [
    ('reencode_only', '크기 유지 · 1280×720 재압축', 'setsar=1'),
    ('upscale_1080', '확대 · 1920×1080', 'scale=1920:1080:flags=bicubic,setsar=1'),
    ('downscale_360', '축소 · 640×360', 'scale=640:360:flags=bicubic,setsar=1'),
    ('downscale_180', '축소 · 320×180', 'scale=320:180:flags=bicubic,setsar=1'),
    ('stretch_wide', '가로 1.5배 신축 · 1920×720', 'scale=1920:720:flags=bicubic,setsar=1'),
    ('stretch_tall', '세로 1.5배 신축 · 1280×1080', 'scale=1280:1080:flags=bicubic,setsar=1'),
    ('zoom_125', '1.25배 확대 후 중앙만 유지 · 원본 면적 64%', 'crop=1024:576:(iw-ow)/2:(ih-oh)/2,scale=1280:720:flags=bicubic,setsar=1'),
    ('zoom_150', '약 1.5배 확대 후 중앙만 유지 · 원본 면적 약 44%', 'crop=854:480:(iw-ow)/2:(ih-oh)/2,scale=1280:720:flags=bicubic,setsar=1'),
    ('zoom_200', '2배 확대 후 중앙만 유지 · 원본 면적 25%', 'crop=640:360:(iw-ow)/2:(ih-oh)/2,scale=1280:720:flags=bicubic,setsar=1'),
    ('zoomout_pad', '75% 축소 후 검은 여백 추가 · 1280×720 캔버스', 'scale=960:540:flags=bicubic,pad=1280:720:(ow-iw)/2:(oh-ih)/2:black,setsar=1'),
]

client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
client.open((ROOT/'data/admin_url.txt').read_text(encoding='utf8'),timeout=30).read()

def request(path, data=None):
    headers = {'X-Forensic-G': '1', 'Content-Type': 'application/octet-stream'} if data is not None else {}
    with client.open(urllib.request.Request(BASE + path, data=data, headers=headers), timeout=30) as r:
        return json.load(r)

def inspect(path):
    pending = request('/api/inspect', path.read_bytes())
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = request('/api/state')
        if not state['busy']:
            if state['job']['id'] != pending['id']:
                raise RuntimeError('Another client started a job; stopping to avoid interfering')
            if state['job']['status'] == 'error':
                raise RuntimeError(state['job']['message'])
            return state['reports'][pending['id']]
        time.sleep(0.4)
    raise TimeoutError('Detector exceeded 120 seconds')

def convert(source, target, vf):
    subprocess.run([CFG['ffmpeg'], '-v', 'error', '-nostdin', '-n', '-i', str(source),
                    '-map', '0:v:0', '-map', '0:a:0?', '-vf', vf,
                    '-c:v', 'libx264', '-preset', 'medium', '-crf', '23', '-pix_fmt', 'yuv420p',
                    '-c:a', 'aac', '-b:a', '128k', '-map_metadata', '-1', str(target)],
                   check=True, timeout=90, creationflags=0x08000000)

def persist():
    raw = json.dumps(result, ensure_ascii=False, indent=2)
    (OUT / 'report.json').write_text(raw, encoding='utf8')
    EXPORT.write_text(raw, encoding='utf8')

state = request('/api/state')
if state['busy']:
    raise RuntimeError('Server is busy; no experiment started')
previous = json.loads((ROOT / 'tests/results/robustness.json').read_text(encoding='utf8'))
deliveries = {entry['delivery']['label']: entry['delivery'] for entry in previous}
result = {'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'scope': 'One synthetic 8-second 720p clip, 2 distinct delivery codes, strength 0.4; unchanged existing C++ executable.',
          'encoding': 'libx264 medium CRF23 yuv420p; no metadata copied; SAR=1',
          'expected_code_used_only_for_scoring': True,
          'engine_sha256': hashlib.sha256((ROOT/'ForensicEngine.dll').read_bytes()).hexdigest(),
          'server_sha256': hashlib.sha256((ROOT/'Forensic_G.exe').read_bytes()).hexdigest(),
          'cases': [], 'complete': False}

for label, delivery in deliveries.items():
    source = ROOT / 'tests/results' / (label + '.mp4')
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    expected = bytes.fromhex(delivery['processing']['channel_recovery']['payload_hex'])
    for name, description, vf in CASES:
        target = OUT / (label + '_' + name + '.mp4')
        convert(source, target, vf)
        report = inspect(target)
        actual = bytes.fromhex(report['payload_hex'])
        matched_id = report.get('delivery', {}).get('id')
        passed = report['status'] == 'matched' and matched_id == delivery['id']
        row = {'copy': label, 'case': name, 'description': description, 'ffmpeg_filter': vf,
               'correct_attribution': passed, 'status': report['status'],
               'raw_bit_errors': sum((a ^ b).bit_count() for a,b in zip(actual,expected)),
               'corrected_bits': report.get('channel_recovery', {}).get('corrected_bits'),
               'expected_delivery_id': delivery['id'], 'matched_delivery_id': matched_id,
               'report_id': report['report_id'], 'video_path': str(target),
               'detector_seconds': report['elapsed_seconds']}
        result['cases'].append(row)
        persist()
        print(label, name, 'MATCH' if passed else 'NOT IDENTIFIED', 'raw errors', row['raw_bit_errors'], flush=True)
        if report['status'] == 'matched' and not passed:
            raise RuntimeError('Wrong attribution observed; stopping')
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before

result['negative_controls'] = []
for name, description, vf in [CASES[4], CASES[6]]:
    target = OUT / ('unwatermarked_' + name + '.mp4')
    convert(ROOT / 'sample.mp4', target, vf)
    report = inspect(target)
    result['negative_controls'].append({'case':name, 'status':report['status'],
        'passed':report['status']=='not_identified' and 'delivery' not in report,
        'report_id':report['report_id']})
    print('Negative', name, report['status'], flush=True)
    persist()

result['summary'] = {name: {'description':desc, 'matches':sum(r['correct_attribution'] for r in result['cases'] if r['case']==name),
                          'tested':sum(1 for r in result['cases'] if r['case']==name)} for name,desc,_ in CASES}
result['complete'] = True
persist()
print('Saved', EXPORT, flush=True)
