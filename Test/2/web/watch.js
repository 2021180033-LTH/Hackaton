'use strict';
const $=s=>document.querySelector(s),assetId=location.pathname.split('/').pop();
let playback=null,timer=null,ready=false;const video=$('#watch-video');
async function api(path,body){const options=body===undefined?{}:{method:'POST',headers:{'X-Forensic-G':'1','Content-Type':'application/json'},body:JSON.stringify(body)};const response=await fetch(path,options);const data=await response.json();if(!response.ok)throw Error(data.error||'요청 실패');return data;}
function error(e){$('#watch-error').textContent=e.message||String(e);$('#watch-error').hidden=false;}
async function poll(){try{const data=await api(playback.status_url);$('#watch-progress').value=data.progress||0;$('#watch-message').textContent=data.message||'영상 사본을 준비하고 있습니다.';
  if(data.status==='ready'){ready=true;$('#watch-progress').value=100;$('#watch-status').textContent='시청 사본 준비 완료';$('#session-info').textContent='이번 재생 세션: '+data.playback_session_id;video.src=data.media_url;$('#viewer-download').href=data.media_url+'?download=1';$('#viewer-download').hidden=false;$('#start-playback').disabled=false;$('#start-playback').textContent='영상 재생 ▶';$('#new-session').hidden=false;try{await video.play();}catch{$('#watch-message').textContent='준비가 끝났습니다. 영상 재생 버튼을 눌러주세요.';}return;}
  if(['error','verification_failed','interrupted'].includes(data.status))throw Error('시청 사본을 준비하지 못했습니다. 새로 시도해 주세요.');timer=setTimeout(poll,1000);
}catch(e){error(e);$('#start-playback').disabled=false;$('#new-session').hidden=false;}}
$('#start-playback').onclick=async()=>{$('#watch-error').hidden=true;if(ready){try{await video.play();}catch(e){error(e);}return;}$('#start-playback').disabled=true;try{playback=await api('/api/playback/start',{asset_id:assetId});$('#watch-job').hidden=false;$('#watch-status').textContent='이 시청 세션용 사본을 준비 중';await poll();}catch(e){error(e);$('#start-playback').disabled=false;}};
$('#new-session').onclick=()=>{clearTimeout(timer);video.pause();video.removeAttribute('src');video.load();ready=false;playback=null;$('#new-session').hidden=true;$('#viewer-download').hidden=true;$('#watch-job').hidden=true;$('#session-info').textContent='';$('#start-playback').textContent='재생 준비 후 시청 →';$('#start-playback').disabled=false;};
async function record(event){if(!ready||!playback)return;try{await api('/api/playback/'+playback.id+'/events',{event,position_seconds:video.currentTime});}catch(e){error('재생 신호 기록에 실패했습니다: '+e.message);}}
video.addEventListener('playing',()=>record('playing'));video.addEventListener('ended',()=>record('ended'));
api('/api/watch/'+assetId).then(data=>{$('#watch-title').textContent=data.name;$('#watch-meta').textContent=data.duration.toFixed(1)+'초 영상 · 재생을 요청하면 나만의 사본이 준비됩니다.';$('#start-playback').disabled=false;}).catch(error);
