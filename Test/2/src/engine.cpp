#define NOMINMAX
#include <torch/script.h>
#include <torch/cuda.h>
#include <ATen/Parallel.h>
#include <atomic>
#include <thread>
#include <cmath>
#include "common.h"
#include "alignment.h"
using namespace fg;
using Progress=void(__cdecl*)(int,const char*,void*);
static std::unique_ptr<torch::jit::Module> model;
static torch::Device dev(torch::kCPU);
static void tick(Progress cb,void*ctx,int n,const std::string&s){if(cb)cb(n,s.c_str(),ctx);}
static torch::jit::Module& load(const json&r){if(!model){at::set_num_threads(4);dev=torch::Device(r.value("device","auto")!="cpu"&&torch::cuda::is_available()?torch::kCUDA:torch::kCPU);auto m=torch::jit::load(r.at("model").get<std::string>(),torch::kCPU);m.eval();m.to(dev);model=std::make_unique<torch::jit::Module>(std::move(m));}return *model;}
static torch::Tensor tensor(const std::vector<unsigned char>& rgb,int h,int w){return torch::from_blob((void*)rgb.data(),{1,h,w,3},torch::kUInt8).permute({0,3,1,2}).to(dev,torch::kFloat32).div(255);}

static torch::Tensor decode_frames(const json&r,const fs::path&input,const std::string&label){
    auto dir=fs::u8path(r.at("job_dir").get<std::string>()),ff=fs::u8path(r.at("ffmpeg").get<std::string>());
    auto info=probe(fs::u8path(r.at("ffprobe").get<std::string>()),input,dir);
    double rate=std::min(24.0,32.0/info["duration"].get<double>());
    auto filter=L"fps="+std::to_wstring(rate)+L",scale=256:256:flags=bicubic";
    Child reader({ff.wstring(),L"-v",L"error",L"-nostdin",L"-protocol_whitelist",L"file,pipe",L"-i",input.wstring(),L"-map",L"0:v:0",L"-an",L"-vf",filter,L"-frames:v",L"32",L"-pix_fmt",L"rgb24",L"-f",L"rawvideo",L"pipe:1"},dir/wide(label+"_decode.log"));
    std::vector<unsigned char>rgb(256*256*3);std::vector<torch::Tensor>frames;
    while(true){auto n=reader.get(rgb.data(),rgb.size());if(!n)break;if(n!=rgb.size())throw std::runtime_error("Incomplete detection frame");frames.push_back(tensor(rgb,256,256));}
    reader.finish();if(frames.empty())throw std::runtime_error("No frames decoded");return torch::cat(frames);
}
static json read_candidate(torch::Tensor frames,const std::string&orientation,const std::string&geometry){
    std::vector<torch::Tensor>results;
    for(auto&chunk:frames.split(4)){
        auto p=model->get_method("detect")({chunk,false}).toTensor().to(torch::kCPU).to(torch::kFloat32);
        if(p.dim()>2)p=p.flatten(2).mean(2);if(p.size(1)!=257)throw std::runtime_error("Unexpected VideoSeal output");results.push_back(p.slice(1,1,257));
    }
    auto each=torch::cat(results),row=each.mean(0).contiguous();auto a=row.accessor<float,1>();
    std::vector<unsigned char>bytes(32,0);for(int i=0;i<256;i++)if(a[i]>0)bytes[i/8]|=1<<(7-i%8);
    std::vector<float>logits(a.data(),a.data()+256);
    return {{"orientation",orientation},{"geometry",geometry},{"payload_hex",hex(bytes.data(),32)},{"bit_logits",logits},{"mean_abs_logit",row.abs().mean().item<double>()},{"frame_bit_agreement",(each.gt(0)==row.gt(0)).to(torch::kFloat32).mean().item<double>()}};
}
static json detect(const json&r,Progress cb,void*ctx){
    auto input=fs::u8path(r.at("input").get<std::string>()),dir=fs::u8path(r.at("job_dir").get<std::string>());
    auto info=probe(fs::u8path(r.at("ffprobe").get<std::string>()),input,dir);load(r);torch::InferenceMode guard;
    auto frames=decode_frames(r,input,"evidence");int orientations=r.value("orientation_search",true)?4:1;
    const char*names[]{"identity","horizontal_flip","vertical_flip","both_flips"};json candidates=json::array(),fits=json::array();
    for(int k=0;k<orientations;k++){tick(cb,ctx,10+k*15,"방향별 식별 코드 읽는 중");candidates.push_back(read_candidate(oriented(frames,k),names[k],"direct"));}
    if(r.value("geometry_search",false)){
        int idx=0;for(auto&ref:r.value("references",json::array())){
            if(idx>=8)break;idx++;tick(cb,ctx,70,"원본 장면 기준으로 크기·위치 보정 중 · "+std::to_string(idx));
            try{
                auto source=decode_frames(r,fs::u8path(ref.at("path").get<std::string>()),"reference_"+std::to_string(idx));auto fit=fit_geometry(source,frames);
                json f={{"reference_asset_id",ref.at("asset_id")},{"orientation",names[fit.orientation]},{"evidence_to_reference",fit.params},{"mean_absolute_error",fit.loss},{"accepted_for_attempt",fit.loss<.08},{"uses_reference_pixels_for_output",false}};
                fits.push_back(f);if(fit.loss>=.08)continue;
                auto candidate=read_candidate(undo_geometry(frames,fit),names[fit.orientation],"reference_alignment");candidate["registration"]=f;candidates.push_back(candidate);
            }catch(const std::exception&e){fits.push_back({{"reference_asset_id",ref.at("asset_id")},{"error",e.what()},{"accepted_for_attempt",false}});}
        }
    }
    return {{"payload_hex",candidates[0]["payload_hex"]},{"sampled_frames",frames.size(0)},{"orientation_candidates",candidates},{"orientation_attempts",orientations},{"candidate_attempts",candidates.size()},{"registration_attempts",fits},{"input",info},{"device",dev.is_cuda()?"CUDA":"CPU"},{"note","Decoded code must pass MAC validation. Reference frames estimate geometry only; missing evidence pixels are zero-filled. Registration is not viewer identification."}};
}
static json embed(const json&r,Progress cb,void*ctx){
    fs::path input=fs::u8path(r.at("input").get<std::string>()),output=fs::u8path(r.at("output").get<std::string>()),dir=fs::u8path(r.at("job_dir").get<std::string>()),ff=fs::u8path(r.at("ffmpeg").get<std::string>());if(fs::exists(output))throw std::runtime_error("Output already exists");auto info=probe(fs::u8path(r.at("ffprobe").get<std::string>()),input,dir);auto bytes=unhex(r.at("payload_hex"));if(bytes.size()!=32)throw std::runtime_error("Expected 256-bit payload");auto&m=load(r);torch::InferenceMode guard;
    double strength=r.value("strength",0.4);if(strength<0.1||strength>0.6)throw std::runtime_error("Invalid watermark strength");m.attr("blender").toModule().setattr("scaling_w",strength);
    double scale=std::min({1.0,1280.0/info["width"].get<int>(),720.0/info["height"].get<int>()});int w=std::max(2,(int)(info["width"].get<int>()*scale)/2*2),h=std::max(2,(int)(info["height"].get<int>()*scale)/2*2);int fps=r.value("fps",24);if(fps!=12&&fps!=24&&fps!=30)throw std::runtime_error("Unsupported fps");
    std::vector<float>message(256);for(int i=0;i<256;i++)message[i]=(bytes[i/8]>>(7-i%8))&1;auto msg=torch::from_blob(message.data(),{1,256},torch::kFloat32).to(dev).clone();
    auto vf=L"scale="+std::to_wstring(w)+L":"+std::to_wstring(h)+L":flags=bicubic,fps="+std::to_wstring(fps);
    Child decoder({ff.wstring(),L"-v",L"error",L"-nostdin",L"-protocol_whitelist",L"file,pipe",L"-i",input.wstring(),L"-map",L"0:v:0",L"-an",L"-vf",vf,L"-pix_fmt",L"rgb24",L"-f",L"rawvideo",L"pipe:1"},dir/L"decode.log");
    Child encoder({ff.wstring(),L"-v",L"error",L"-nostdin",L"-n",L"-f",L"rawvideo",L"-pix_fmt",L"rgb24",L"-s",std::to_wstring(w)+L"x"+std::to_wstring(h),L"-r",std::to_wstring(fps),L"-i",L"pipe:0",L"-protocol_whitelist",L"file,pipe",L"-i",input.wstring(),L"-map",L"0:v:0",L"-map",L"1:a:0?",L"-c:v",L"libx264",L"-preset",L"veryfast",L"-crf",L"18",L"-pix_fmt",L"yuv420p",L"-c:a",L"aac",L"-b:a",L"128k",L"-movflags",L"+faststart",L"-map_metadata",L"-1",output.wstring()},dir/L"encode.log",true);
    size_t framebytes=(size_t)w*h*3;std::vector<unsigned char>rgb(framebytes);int frames=0;bool end=false;double squared=0;size_t values=0;while(!end){std::vector<torch::Tensor>chunk;for(int i=0;i<4;i++){size_t n=decoder.get(rgb.data(),framebytes);if(!n){end=true;break;}if(n!=framebytes)throw std::runtime_error("Truncated input frame");chunk.push_back(tensor(rgb,h,w));}if(chunk.empty())break;auto x=torch::cat(chunk);auto y=m.get_method("embed")({x,msg,true}).toTensor().clamp(0,1);squared+=(y-x).square().sum().item<double>();values+=y.numel();auto out=y.mul(255).round().to(torch::kUInt8).permute({0,2,3,1}).contiguous().cpu();encoder.put(out.data_ptr(),out.numel());frames+=(int)chunk.size();tick(cb,ctx,std::min(88,5+(int)(83*frames/(info["duration"].get<double>()*fps))),"VideoSeal 삽입 중 · "+std::to_string(frames)+" 프레임");}decoder.finish();encoder.finish();if(!frames)throw std::runtime_error("No frames processed");
    tick(cb,ctx,90,"저장된 MP4에서 코드 재검출 중");json check=r;check["input"]=output.u8string();check["orientation_search"]=false;auto verified=detect(check,nullptr,nullptr);bool exact=verified["payload_hex"]==r["payload_hex"];
    return {{"frames",frames},{"width",w},{"height",h},{"fps",fps},{"strength",strength},{"device",dev.is_cuda()?"CUDA":"CPU"},{"pre_encode_psnr_db",squared>0?10*std::log10(values/squared):99.0},{"saved_mp4_exact_match",exact},{"verification",verified},{"output",output.u8string()}};
}
extern "C" __declspec(dllexport) int __cdecl FGRun(const char* request,Progress cb,void*ctx,char* error,int capacity){try{auto start=std::chrono::steady_clock::now();auto r=json::parse(request);fs::path dir=fs::u8path(r.at("job_dir").get<std::string>());fs::create_directories(dir);tick(cb,ctx,1,"VideoSeal 모델 준비 중");auto result=r.value("operation","")=="embed"?embed(r,cb,ctx):detect(r,cb,ctx);result["elapsed_seconds"]=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();atomic_json(dir/L"engine_result.json",result);tick(cb,ctx,100,"완료");return 0;}catch(const std::exception&e){strncpy_s(error,capacity,e.what(),_TRUNCATE);return 1;}}
