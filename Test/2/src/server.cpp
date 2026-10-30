#define NOMINMAX
#include "../third_party/httplib.h"
#include "common.h"
#include "watermark_code.h"
#include <shellapi.h>
#include <mutex>
#include <iostream>
#include <regex>
#include <set>
using namespace fg;
using Progress=void(__cdecl*)(int,const char*,void*);
using Run=int(__cdecl*)(const char*,Progress,void*,char*,int);
static fs::path root;static json config,db;static std::string key;static std::mutex mu;static std::atomic<bool> busy{false};static json job={{"status","idle"}};static Run engine=nullptr;static std::thread worker;
static void save(){atomic_json(root/L"data/ledger.json",db);}
static std::string new_id(const char* kind){std::string id;do{id=random_hex(8);}while(db[kind].contains(id));return id;}
static std::string cookie(const httplib::Request&r,const std::string&name){auto s=r.get_header_value("Cookie");std::regex re("(?:^|; *)"+name+"=([a-f0-9]{32})(?:;|$)");std::smatch m;return std::regex_search(s,m,re)?m[1].str():"";}
static std::string identity(const httplib::Request&r,httplib::Response&res,const std::string&name,bool persistent){auto id=cookie(r,name);if(id.empty()){id=random_hex(16);res.headers.emplace("Set-Cookie",name+"="+id+"; Path=/; HttpOnly; SameSite=Strict"+(persistent?"; Max-Age=2592000":""));}return id;}
static std::string payload(const std::string&asset,const std::string&delivery){auto head=unhex("46470100"+asset+delivery);std::string body((char*)head.data(),head.size());return hex(head.data(),head.size())+sha(body,key).substr(0,24);}
static bool authentic(const std::string&hexed){if(hexed.size()!=64||hexed.substr(0,8)!="46470100")return false;auto all=unhex(hexed);auto h=sha(std::string((char*)all.data(),20),key).substr(0,24);unsigned char delta=0;for(int i=0;i<24;i++)delta|=h[i]^hexed[40+i];return delta==0;}
// A bounded channel-error repair, independent of the issuance ledger.
// Only a unique code satisfying the 96-bit keyed MAC can be accepted.
// This does not turn a nearest-neighbour or a similarity score into an identity.
static json recover(const std::string&raw){
    if(authentic(raw))return {{"valid",true},{"payload_hex",raw},{"corrected_bits",0}};
    auto bytes=unhex(raw);if(bytes.size()!=32)return {{"valid",false}};
    auto pop=[](unsigned char b){int n=0;while(b){n+=b&1;b>>=1;}return n;};
    unsigned char magic[]{0x46,0x47,0x01,0};int header_errors=0;for(int i=0;i<4;i++)header_errors+=pop(bytes[i]^magic[i]);if(header_errors>2)return {{"valid",false}};
    std::string winner;int errors=0,count=0;auto flip=[&](int i){bytes[i/8]^=1<<(7-i%8);};auto test=[&](int bits){auto candidate=hex(bytes.data(),32);if(authentic(candidate)){winner=candidate;errors=bits;count++;}};
    for(int i=0;i<256;i++){flip(i);test(1);for(int j=i+1;j<256;j++){flip(j);test(2);flip(j);}flip(i);}
    if(count==1)return {{"valid",true},{"payload_hex",winner},{"corrected_bits",errors}};
    return {{"valid",false},{"ambiguous",count>1}};
}
static json recover_orientations(const json&r){
    auto candidates=r.value("orientation_candidates",json::array({{{"orientation","identity"},{"payload_hex",r.at("payload_hex")}}}));
    std::map<std::string,json> valid;
    for(auto&c:candidates){auto d=ecc_decode(c.at("payload_hex"),key,c.value("bit_logits",std::vector<float>{}));if(!d.value("valid",false))d=recover(c.at("payload_hex"));if(!d.value("valid",false))continue;
        d["orientation"]=c.value("orientation","identity");auto code=d["payload_hex"].get<std::string>();
        d["geometry"]=c.value("geometry","direct");
        if(!valid.count(code)||d["corrected_bits"].get<int>()<valid[code]["corrected_bits"].get<int>())valid[code]=d;
    }
    if(valid.size()==1){auto d=valid.begin()->second;d["orientation_attempts"]=candidates.size();return d;}
    return {{"valid",false},{"ambiguous",valid.size()>1},{"orientation_attempts",candidates.size()}};
}
static std::string admin_token(){return sha("Forensic_G admin capability v2",key).substr(0,32);}
static bool is_admin(const httplib::Request&r){auto c=cookie(r,"fg_admin");return !c.empty()&&c==admin_token();}
static bool owns_playback(const httplib::Request&r,const json&d){auto c=cookie(r,"fg_viewer");return d.value("issuance_context","")=="viewer_playback"&&!c.empty()&&c==d.value("viewer_browser_id","");}
static json view_delivery(json d){d.erase("payload_hex");d.erase("path");return d;}
static void result(httplib::Response&res,const json&j,int status=200){res.status=status;res.set_content(j.dump(),"application/json; charset=utf-8");res.set_header("Cache-Control","no-store");}
static void fail(httplib::Response&res,const std::string&s,int status=400){result(res,{{"error",s}},status);}
static void serve_video(httplib::Response&res,const std::string&filename){
    auto path=fs::u8path(filename);auto size=fs::file_size(path);res.set_header("Accept-Ranges","bytes");
    // Supply length before httplib validates Range (set_file_content in 0.18.3
    // initializes the provider too late for range validation).
    res.set_content_provider((size_t)size,"video/mp4",[path](size_t offset,size_t length,httplib::DataSink&sink){std::ifstream in(path,std::ios::binary);if(!in)return false;in.seekg((std::streamoff)offset);char buffer[65536];while(length){auto n=std::min(length,sizeof buffer);in.read(buffer,n);if((size_t)in.gcount()!=n||!sink.write(buffer,n))return false;length-=n;}return true;});
}
static void progress(int n,const char*message,void*){std::lock_guard<std::mutex>lock(mu);job["progress"]=n;job["message"]=message;}
static void load_engine(){if(engine)return;auto lib=fs::u8path(config.at("libtorch").get<std::string>());SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);AddDllDirectory(lib.c_str());if(fs::exists(lib/L"torch_cuda.dll"))LoadLibraryExW((lib/L"torch_cuda.dll").c_str(),nullptr,LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);auto dll=LoadLibraryExW((root/L"ForensicEngine.dll").c_str(),nullptr,LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);if(!dll)throw std::runtime_error("Engine load failed: "+std::to_string(GetLastError()));engine=(Run)GetProcAddress(dll,"FGRun");if(!engine)throw std::runtime_error("Missing FGRun export");}
static void launch(json req,const std::string&kind,const std::string&id){
    if(worker.joinable())worker.join();
    {std::lock_guard<std::mutex>lock(mu);job={{"status","running"},{"kind",kind},{"id",id},{"progress",0},{"message","작업 시작"},{"started_at",now()}};}
    worker=std::thread([req,kind,id]()mutable{try{
        load_engine();for(auto&[k,v]:config.items())if(k=="ffmpeg"||k=="ffprobe"||k=="libtorch"||k=="device")req[k]=v;req["model"]=(root/L"models/y_256b_img.jit").u8string();char error[8192]{};if(engine(req.dump().c_str(),progress,nullptr,error,sizeof error))throw std::runtime_error(error);auto r=json::parse(read(fs::u8path(req["job_dir"].get<std::string>())/L"engine_result.json"));
        if(kind=="inspect"&&!recover_orientations(r).value("valid",false)&&!req.value("references",json::array()).empty()){
            auto first_seconds=r.value("elapsed_seconds",0.0);req["geometry_search"]=true;progress(65,"식별 재시도 · 원본 기준 보정",nullptr);
            if(engine(req.dump().c_str(),progress,nullptr,error,sizeof error))throw std::runtime_error(error);
            r=json::parse(read(fs::u8path(req["job_dir"].get<std::string>())/L"engine_result.json"));r["elapsed_seconds"]=first_seconds+r.value("elapsed_seconds",0.0);r["geometry_fallback_used"]=true;
        }
        std::lock_guard<std::mutex>lock(mu);
        if(kind=="issue"){
            auto&d=db["deliveries"][id];auto decoded=recover_orientations(r["verification"]);bool ok=decoded.value("valid",false)&&decoded.value("payload_hex","")==d["payload_hex"];r["saved_mp4_authenticated_match"]=ok;r["channel_recovery"]=decoded;d["status"]=ok?"ready":"verification_failed";d["processing"]=r;d["completed_at"]=now();job["message"]=ok?"시청 세션용 사본 준비 완료":"삽입 후 코드 검증 실패 · 배포하지 않음";
        }else{
            auto decoded=recover_orientations(r);r["channel_recovery"]=decoded;r["report_id"]=id;r["created_at"]=now();r["status"]="not_identified";r["identity_proven"]=false;r["reason"]="유효한 등록 배포 코드를 복원하지 못했습니다.";
            if(decoded.value("valid",false)){auto code=decoded["payload_hex"].get<std::string>();auto did=decoded.value("delivery_id",code.substr(24,16));auto aid=decoded.contains("delivery_id")&&db["deliveries"].contains(did)?db["deliveries"][did]["asset_id"].get<std::string>():code.substr(8,16);if(db["deliveries"].contains(did)&&db["deliveries"][did]["asset_id"]==aid&&db["deliveries"][did]["payload_hex"]==code&&db["deliveries"][did]["status"]=="ready"){r["status"]="matched";r["reason"]="복원한 코드가 등록된 배포 사본과 일치하며 HMAC 검증을 통과했습니다. 보정 비트: "+std::to_string(decoded.value("corrected_bits",0));r["delivery"]=view_delivery(db["deliveries"][did]);r["asset"]=db["assets"][aid];r["asset"].erase("path");}else{r["status"]="unregistered";r["reason"]="인증 코드는 유효하지만 발급 완료 기록이 없습니다.";}}
            // Never attach an identity to a nearest-bit candidate. No fuzzy attribution.
            db["reports"][id]=r;atomic_json(fs::u8path(req["job_dir"].get<std::string>())/L"report.json",r);job["message"]=r["status"]=="matched"?"검사 완료 · 배포 사본 일치":"검사 완료 · 식별 불가";
        }
        job["status"]="done";job["progress"]=100;save();
    }catch(const std::exception&e){std::lock_guard<std::mutex>lock(mu);job["status"]="error";job["message"]=e.what();if(kind=="issue"){db["deliveries"][id]["status"]="error";db["deliveries"][id]["error"]=e.what();}try{save();}catch(...){} }busy=false;});
}
static void init(){
    config=json::parse(read(root/L"config.json"));fs::create_directories(root/L"data/assets");fs::create_directories(root/L"data/jobs");fs::create_directories(root/L"data/deliveries");auto kp=root/L"data/secret.dpapi";
    if(fs::exists(kp)){auto s=read(kp);DATA_BLOB in{(DWORD)s.size(),(BYTE*)s.data()},out{};if(!CryptUnprotectData(&in,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out))throw std::runtime_error("Cannot unlock ledger key for this Windows account");key.assign((char*)out.pbData,out.cbData);LocalFree(out.pbData);}else{if(fs::exists(root/L"data/ledger.json"))throw std::runtime_error("Ledger exists but its signing key is missing");auto b=unhex(random_hex(32));key.assign((char*)b.data(),b.size());DATA_BLOB in{(DWORD)key.size(),(BYTE*)key.data()},out{};if(!CryptProtectData(&in,L"Forensic_G ledger",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out))throw std::runtime_error("Key protection failed");write(kp,std::string((char*)out.pbData,out.cbData));LocalFree(out.pbData);}
    db=fs::exists(root/L"data/ledger.json")?json::parse(read(root/L"data/ledger.json")):json{{"version",1},{"assets",json::object()},{"deliveries",json::object()},{"reports",json::object()}};for(auto&[id,d]:db["deliveries"].items())if(d["status"]=="processing")d["status"]="interrupted";save();
}
static int self_test(){key="Forensic_G test key (not a production key)";auto original=payload("0123456789abcdef","fedcba9876543210");json tests=json::array();for(auto positions:std::vector<std::vector<int>>{{},{0},{32},{127},{255},{0,255},{64,100},{224,250},{20,60,240}}){auto b=unhex(original);for(int i:positions)b[i/8]^=1<<(7-i%8);auto start=std::chrono::steady_clock::now();auto d=recover(hex(b.data(),32));bool pass=positions.size()<=2?(d.value("valid",false)&&d.value("payload_hex","")==original&&d.value("corrected_bits",-1)==positions.size()):!d.value("valid",false);tests.push_back({{"flipped_bits",positions},{"passed",pass},{"seconds",std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count()}});}auto old=key;key="Wrong signing key";tests.push_back({{"name","Wrong signing key rejected"},{"passed",!recover(original).value("valid",false)}});key=old;tests.push_back({{"name","Blank payload rejected"},{"passed",!recover(std::string(64,'0')).value("valid",false)}});atomic_json(root/L"tests/results/payload_tests.json",tests);bool pass=true;for(auto&t:tests)pass=pass&&t["passed"].get<bool>();std::cout<<tests.dump(2)<<"\n";return pass?0:1;}
int wmain(int argc,wchar_t**argv){try{
    wchar_t path[32768];GetModuleFileNameW(nullptr,path,32768);root=fs::path(path).parent_path();SetConsoleOutputCP(CP_UTF8);if(argc>1&&std::wstring(argv[1])==L"--self-test")return self_test();Handle mutex(CreateMutexW(nullptr,FALSE,wide("Local\\Forensic_G_"+sha(root.u8string()).substr(0,16)).c_str()));if(GetLastError()==ERROR_ALREADY_EXISTS){auto url=wide(read(root/L"data/admin_url.txt"));ShellExecuteW(nullptr,L"open",url.c_str(),nullptr,nullptr,SW_SHOWNORMAL);std::cout<<"Opened existing Forensic_G server.\n";return 0;}init();int port=config.value("port",8769);bool open=true;for(int i=1;i<argc;i++){if(std::wstring(argv[i])==L"--no-browser")open=false;if(std::wstring(argv[i])==L"--port"&&i+1<argc)port=std::stoi(argv[++i]);}if(port<1024||port>65535)throw std::runtime_error("Invalid port");
    httplib::Server server;server.new_task_queue=[] {return new httplib::ThreadPool(4);};server.set_payload_max_length(100*1024*1024);server.set_read_timeout(60);server.set_write_timeout(60);server.set_keep_alive_max_count(10);
    auto origin="http://127.0.0.1:"+std::to_string(port);auto other="http://localhost:"+std::to_string(port);
    server.set_pre_routing_handler([&](const httplib::Request&r,httplib::Response&res){res.set_header("Cache-Control","no-store");res.set_header("X-Content-Type-Options","nosniff");res.set_header("Referrer-Policy","no-referrer");res.set_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; media-src 'self' blob:; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'");auto host=r.get_header_value("Host");if(host!=origin.substr(7)&&host!=other.substr(7)){fail(res,"Invalid host",403);return httplib::Server::HandlerResponse::Handled;}if(r.method=="POST"&&(r.get_header_value("X-Forensic-G")!="1"||(!r.get_header_value("Origin").empty()&&r.get_header_value("Origin")!=origin&&r.get_header_value("Origin")!=other))){fail(res,"Invalid local request",403);return httplib::Server::HandlerResponse::Handled;}bool admin_route=r.path=="/api/state"||r.path=="/api/assets"||r.path=="/api/inspect"||r.path=="/api/issue"||r.path.rfind("/original/",0)==0||r.path.rfind("/report/",0)==0;
        if(admin_route&&!is_admin(r)){fail(res,"관리자 권한이 필요합니다. 제작자 PC에서 Forensic_G.exe를 실행하세요.",403);return httplib::Server::HandlerResponse::Handled;}
        return httplib::Server::HandlerResponse::Unhandled;});
    server.set_exception_handler([](const auto&,auto&res,std::exception_ptr ep){try{std::rethrow_exception(ep);}catch(const std::exception&e){fail(res,e.what(),500);}catch(...){fail(res,"Unknown error",500);}});
    server.Get(R"(/admin/([a-f0-9]{32}))",[](const auto&r,auto&res){
        if(r.matches[1].str()!=admin_token()){fail(res,"Invalid admin capability",403);return;}
        res.headers.emplace("Set-Cookie","fg_admin="+admin_token()+"; Path=/; HttpOnly; SameSite=Strict");res.set_redirect("/",303);
    });
    server.Get("/",[](const auto&r,auto&res){
        if(is_admin(r)){res.set_content(read(root/L"web/index.html"),"text/html; charset=utf-8");return;}
        res.set_content("<!doctype html><html lang=ko><meta charset=utf-8><title>Forensic G</title><link rel=stylesheet href=/style.css><body class=viewer-body><main class=viewer-main><div class=card><h1>Forensic G</h1><p>제작자에게 받은 시청 링크로 영상을 열어주세요.</p><p>제작자 관리 화면은 이 PC에서 Forensic_G.exe를 실행하면 열립니다.</p></div></main></body></html>","text/html; charset=utf-8");
    });
    server.Get(R"(/watch/([a-f0-9]{16}))",[](const auto&r,auto&res){
        {std::lock_guard<std::mutex>lock(mu);if(!db["assets"].contains(r.matches[1].str())){fail(res,"영상이 없습니다.",404);return;}}
        identity(r,res,"fg_viewer",true);res.set_content(read(root/L"web/watch.html"),"text/html; charset=utf-8");
    });
    server.Get("/watch.js",[](const auto&,auto&res){res.set_content(read(root/L"web/watch.js"),"text/javascript; charset=utf-8");});
    server.Get(R"(/api/watch/([a-f0-9]{16}))",[](const auto&r,auto&res){
        std::lock_guard<std::mutex>lock(mu);auto aid=r.matches[1].str();if(!db["assets"].contains(aid)){fail(res,"영상이 없습니다.",404);return;}
        auto&a=db["assets"][aid];result(res,{{"asset_id",aid},{"name",a["name"]},{"duration",a["media"]["duration"]}});
    });
    server.Get("/app.js",[](const auto&,auto&res){res.set_content(read(root/L"web/app.js"),"text/javascript; charset=utf-8");});server.Get("/style.css",[](const auto&,auto&res){res.set_content(read(root/L"web/style.css"),"text/css; charset=utf-8");});
    server.Get("/api/state",[](const auto&,auto&res){std::lock_guard<std::mutex>lock(mu);json a=db["assets"],d=db["deliveries"];for(auto&[id,v]:a.items())v.erase("path");for(auto&[id,v]:d.items())v=view_delivery(v);result(res,{{"assets",a},{"deliveries",d},{"reports",db["reports"]},{"job",job},{"busy",busy.load()},{"mode","loopback_only"}});});
    server.Post("/api/assets",[](const auto&r,auto&res){if(r.body.empty()){fail(res,"영상을 선택하세요.");return;}if(busy.exchange(true)){fail(res,"현재 작업이 끝난 뒤 등록하세요.",409);return;}struct Release{~Release(){busy=false;}} release;
        std::string id=random_hex(8);auto dir=root/L"data/assets"/wide(id);fs::create_directories(dir);auto input=dir/L"original.mp4";write(input,r.body);try{auto info=probe(fs::u8path(config["ffprobe"].get<std::string>()),input,dir);auto name=httplib::detail::decode_url(r.get_header_value("X-Filename"),false);if(name.empty())name="video.mp4";if(name.size()>200){size_t end=200;while(end>0&&((unsigned char)name[end]&0xc0)==0x80)--end;name.resize(end);}json a={{"id",id},{"name",name},{"sha256",sha(r.body)},{"bytes",r.body.size()},{"created_at",now()},{"path",input.u8string()},{"media",info}};{std::lock_guard<std::mutex>lock(mu);db["assets"][id]=a;save();}a.erase("path");result(res,a,201);}catch(...){std::error_code ec;fs::remove(input,ec);throw;}});
    server.Post("/api/issue",[](const auto&,auto&res){fail(res,"제작자 대신 발급하는 API는 종료했습니다. 시청 링크에서 /api/playback/start를 호출하세요.",410);});
    server.Post("/api/playback/start",[](const auto&r,auto&res){
        auto q=json::parse(r.body);std::string aid=q.at("asset_id");
        auto viewer=cookie(r,"fg_viewer");if(viewer.empty()){fail(res,"시청 페이지를 먼저 열어주세요.",403);return;}
        if(busy.exchange(true)){fail(res,"다른 영상을 준비하고 있습니다. 잠시 후 다시 재생해 주세요.",409);return;}
        try{
            std::string id;json d;
            {std::lock_guard<std::mutex>lock(mu);if(!db["assets"].contains(aid))throw std::runtime_error("Unknown asset");
                id=new_id("deliveries");auto dir=root/L"data/deliveries"/wide(id);fs::create_directories(dir);
                auto session=random_hex(16);
                d={{"id",id},{"asset_id",aid},{"issuance_context","viewer_playback"},{"label","시청 세션 "+session.substr(0,8)},
                   {"label_verified",false},{"issued_at",now()},{"request_ip",r.remote_addr},{"viewer_request_ip",r.remote_addr},
                   {"viewer_browser_id",viewer},{"browser_id",viewer},{"session_id",session},{"playback_session_id",session},
                   {"user_agent",r.get_header_value("User-Agent").substr(0,512)},
                   {"status","processing"},{"payload_hex",ecc_payload(id,key)},{"payload_format","bch255_131_hmac64_v3"},{"path",(dir/L"watermarked.mp4").u8string()},
                   {"accesses",json::array()},{"playback_events",json::array()}};
                db["deliveries"][id]=d;save();
                q={{"operation","embed"},{"input",db["assets"][aid]["path"]},{"output",d["path"]},{"payload_hex",d["payload_hex"]},
                   {"job_dir",dir.u8string()},{"strength",config.value("watermark_strength",0.6)},{"fps",24}};
            }
            launch(q,"issue",id);result(res,{{"id",id},{"status","processing"},{"status_url","/api/playback/"+id}},202);
        }catch(...){busy=false;throw;}
    });
    server.Get(R"(/api/playback/([a-f0-9]{16}))",[](const auto&r,auto&res){
        std::lock_guard<std::mutex>lock(mu);auto id=r.matches[1].str();
        if(!db["deliveries"].contains(id)||!owns_playback(r,db["deliveries"][id])){fail(res,"이 시청 세션의 사본이 아닙니다.",403);return;}
        auto&d=db["deliveries"][id];json out={{"id",id},{"status",d["status"]},{"playback_session_id",d["playback_session_id"]}};
        if(d["status"]=="ready")out["media_url"]="/stream/"+id;
        if(job.value("id","")==id){out["progress"]=job.value("progress",0);out["message"]=job.value("message","");}
        result(res,out);
    });
    server.Post(R"(/api/playback/([a-f0-9]{16})/events)",[](const auto&r,auto&res){
        auto q=json::parse(r.body);auto event=q.value("event","");double position=q.value("position_seconds",0.0);
        if((event!="playing"&&event!="ended")||!std::isfinite(position)||position<0||position>31){fail(res,"Invalid playback event");return;}
        std::lock_guard<std::mutex>lock(mu);auto id=r.matches[1].str();
        if(!db["deliveries"].contains(id)||!owns_playback(r,db["deliveries"][id])){fail(res,"이 시청 세션의 사본이 아닙니다.",403);return;}
        auto&d=db["deliveries"][id];if(d["status"]!="ready"||!d.contains("first_media_request_at")){fail(res,"미디어 전송 전의 재생 신호입니다.",409);return;}
        if(d["playback_events"].size()<100){d["playback_events"].push_back({{"event",event},{"server_time",now()},{"ip",r.remote_addr},{"position_seconds",position},{"evidence_type","client_reported"}});save();}
        result(res,{{"recorded",true},{"evidence_type","client_reported"}});
    });
    server.Get(R"(/stream/([a-f0-9]{16}))",[](const auto&r,auto&res){
        std::lock_guard<std::mutex>lock(mu);auto id=r.matches[1].str();
        if(!db["deliveries"].contains(id)||!owns_playback(r,db["deliveries"][id])){fail(res,"이 시청 세션의 사본이 아닙니다.",403);return;}
        auto&d=db["deliveries"][id];if(d["status"]!="ready"){fail(res,"사본 준비가 완료되지 않았습니다.",409);return;}
        if(!d.contains("first_media_request_at")){d["first_media_request_at"]=now();d["first_media_request_ip"]=r.remote_addr;}
        if(d["accesses"].size()<100)d["accesses"].push_back({{"time",now()},{"ip",r.remote_addr},{"browser_id",cookie(r,"fg_viewer")},{"event","media_request"}});
        save();res.set_header("Cache-Control","private, no-store");
        if(r.has_param("download"))res.set_header("Content-Disposition","attachment; filename=Forensic_G_viewer_"+id+".mp4");
        serve_video(res,d["path"].get<std::string>());
    });
    server.Post("/api/inspect",[](const auto&r,auto&res){
        if(r.body.empty()){fail(res,"검사할 영상을 선택하세요.");return;}
        json refs=json::array();auto selected=r.get_header_value("X-Reference-Asset");
        {std::lock_guard<std::mutex>lock(mu);std::set<std::string>seen;
            if(!selected.empty()&&selected!="auto"&&selected!="none"&&!db["assets"].contains(selected)){fail(res,"등록되지 않은 기준 원본입니다.");return;}
            if(selected!="none")for(auto&[aid,a]:db["assets"].items())if((selected.empty()||selected=="auto"||selected==aid)&&seen.insert(a["sha256"].get<std::string>()).second){refs.push_back({{"asset_id",aid},{"path",a["path"]},{"media",a["media"]}});if(refs.size()>=8)break;}
        }
        if(busy.exchange(true)){fail(res,"다른 작업이 진행 중입니다.",409);return;}
        try{auto id=random_hex(8);auto dir=root/L"data/jobs"/wide(id);fs::create_directories(dir);auto input=dir/L"evidence.mp4";write(input,r.body);
            launch({{"operation","detect"},{"input",input.u8string()},{"job_dir",dir.u8string()},{"references",refs}},"inspect",id);result(res,{{"id",id}},202);
        }catch(...){busy=false;throw;}
    });
    server.Get(R"(/media/([a-f0-9]{16}))",[](const auto&r,auto&res){std::lock_guard<std::mutex>lock(mu);auto id=r.matches[1].str();if(!db["deliveries"].contains(id)||db["deliveries"][id]["status"]!="ready"){fail(res,"발급 검증을 통과한 사본만 제공됩니다.",404);return;}auto&d=db["deliveries"][id];if(d.value("issuance_context","")=="viewer_playback"){fail(res,"시청자 사본은 해당 시청자의 /stream 주소로만 제공됩니다.",403);return;}if(!is_admin(r)){fail(res,"관리자 권한이 필요합니다.",403);return;}auto&events=d["accesses"];if(events.size()<100)events.push_back({{"time",now()},{"ip",r.remote_addr},{"browser_id",cookie(r,"fg_browser")},{"session_id",cookie(r,"fg_session")}});save();res.set_header("Cache-Control","private, no-store");if(r.has_param("download"))res.set_header("Content-Disposition","attachment; filename=Forensic_G_"+id+".mp4");serve_video(res,d["path"].get<std::string>());});
    server.Get(R"(/original/([a-f0-9]{16}))",[](const auto&r,auto&res){std::lock_guard<std::mutex>lock(mu);auto id=r.matches[1].str();if(!db["assets"].contains(id)){fail(res,"Not found",404);return;}serve_video(res,db["assets"][id]["path"].get<std::string>());});
    server.Get(R"(/report/([a-f0-9]{16}))",[](const auto&r,auto&res){std::lock_guard<std::mutex>lock(mu);auto id=r.matches[1].str();if(!db["reports"].contains(id)){fail(res,"Not found",404);return;}res.set_header("Content-Disposition","attachment; filename=Forensic_G_report_"+id+".json");result(res,db["reports"][id]);});
    if(!server.bind_to_port("127.0.0.1",port))throw std::runtime_error("Local port is in use: "+std::to_string(port));std::cout<<"Forensic_G ready: "<<origin<<"\nLocal-only demo. Close this console to stop.\n"<<std::flush;auto admin_url=origin+"/admin/"+admin_token();write(root/L"data/admin_url.txt",admin_url);if(open)ShellExecuteW(nullptr,L"open",wide(admin_url).c_str(),nullptr,nullptr,SW_SHOWNORMAL);server.listen_after_bind();if(worker.joinable())worker.join();return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<"\n";if(worker.joinable())worker.join();return 1;}}
