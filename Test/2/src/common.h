#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <atomic>
#include <thread>
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include "../third_party/json.hpp"
namespace fg {
namespace fs=std::filesystem;
using json=nlohmann::json;
inline std::wstring wide(const std::string& s){if(s.empty())return {};int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),(int)s.size(),nullptr,0);if(!n)throw std::runtime_error("Invalid UTF-8");std::wstring w(n,0);MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),w.data(),n);return w;}
inline std::string utf8(const std::wstring& s){if(s.empty())return {};int n=WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0,nullptr,nullptr);std::string t(n,0);WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),t.data(),n,nullptr,nullptr);return t;}
inline std::string read(const fs::path& p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("Cannot read: "+p.u8string());return {std::istreambuf_iterator<char>(f),{}};}
inline void write(const fs::path& p,const std::string& s){fs::create_directories(p.parent_path());std::ofstream f(p,std::ios::binary|std::ios::trunc);f.write(s.data(),s.size());f.close();if(!f)throw std::runtime_error("Cannot write: "+p.u8string());}
inline void atomic_json(const fs::path& p,const json& j){auto tmp=p;tmp+=L".tmp";write(tmp,j.dump(2));if(!MoveFileExW(tmp.c_str(),p.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))throw std::runtime_error("Cannot commit ledger");}
inline std::string hex(const unsigned char* p,size_t n){const char* digits="0123456789abcdef";std::string s;for(size_t i=0;i<n;i++){s+=digits[p[i]>>4];s+=digits[p[i]&15];}return s;}
inline std::vector<unsigned char> unhex(const std::string& s){if(s.size()%2)throw std::runtime_error("Invalid hex");std::vector<unsigned char> out;auto val=[](char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw std::runtime_error("Invalid hex");};for(size_t i=0;i<s.size();i+=2)out.push_back((unsigned char)((val(s[i])<<4)|val(s[i+1])));return out;}
inline std::string random_hex(size_t n){std::vector<unsigned char>b(n);if(BCryptGenRandom(nullptr,b.data(),(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw std::runtime_error("Random generation failed");return hex(b.data(),n);}
inline std::string sha(const std::string& data,const std::string& key={}){BCRYPT_ALG_HANDLE a=nullptr;BCRYPT_HASH_HANDLE h=nullptr;if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,key.empty()?0:BCRYPT_ALG_HANDLE_HMAC_FLAG)<0)throw std::runtime_error("SHA init failed");unsigned char out[32];auto status=BCryptCreateHash(a,&h,nullptr,0,key.empty()?nullptr:(PUCHAR)key.data(),(ULONG)key.size(),0);if(status>=0)status=BCryptHashData(h,(PUCHAR)data.data(),(ULONG)data.size(),0);if(status>=0)status=BCryptFinishHash(h,out,32,0);if(h)BCryptDestroyHash(h);BCryptCloseAlgorithmProvider(a,0);if(status<0)throw std::runtime_error("SHA failed");return hex(out,32);}
inline std::string now(){SYSTEMTIME s;GetSystemTime(&s);char b[40];sprintf_s(b,"%04u-%02u-%02uT%02u:%02u:%02uZ",s.wYear,s.wMonth,s.wDay,s.wHour,s.wMinute,s.wSecond);return b;}
inline std::wstring quote(const std::wstring& arg){std::wstring out=L"\"";size_t slashes=0;for(wchar_t c:arg){if(c==L'\\'){slashes++;continue;}out.append(slashes*(c==L'"'?2:1),L'\\');if(c==L'"')out+=L'\\';out+=c;slashes=0;}out.append(slashes*2,L'\\');return out+L'"';}
struct Handle {HANDLE h=nullptr;Handle()=default;explicit Handle(HANDLE v):h(v){}~Handle(){reset();}Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;void reset(HANDLE v=nullptr){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);h=v;}};
// No shell; only these child's standard handles are inheritable. IO bounded by a watchdog.
class Child {
    Handle proc,in,out;bool done=false;std::atomic<bool> stop{false};std::thread watch;
public:
    Child(const std::vector<std::wstring>& args,const fs::path& log,bool input=false){
        SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE r,w;
        if(!CreatePipe(&r,&w,&sa,65536))throw std::runtime_error("Pipe failed");out.reset(r);Handle childout(w);SetHandleInformation(r,HANDLE_FLAG_INHERIT,0);
        Handle childin;
        if(input){if(!CreatePipe(&r,&w,&sa,65536))throw std::runtime_error("Pipe failed");childin.reset(r);in.reset(w);SetHandleInformation(w,HANDLE_FLAG_INHERIT,0);}else childin.reset(CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr));
        Handle err(CreateFileW(log.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&sa,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr));
        if(err.h==INVALID_HANDLE_VALUE)throw std::runtime_error("Log open failed");
        SIZE_T n=0;InitializeProcThreadAttributeList(nullptr,1,0,&n);std::vector<unsigned char>b(n);auto list=(LPPROC_THREAD_ATTRIBUTE_LIST)b.data();if(!InitializeProcThreadAttributeList(list,1,0,&n))throw std::runtime_error("Process init failed");HANDLE handles[]{childin.h,childout.h,err.h};
        if(!UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,handles,sizeof(handles),nullptr,nullptr)){DeleteProcThreadAttributeList(list);throw std::runtime_error("Process handles failed");}
        STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=childin.h;si.StartupInfo.hStdOutput=childout.h;si.StartupInfo.hStdError=err.h;si.lpAttributeList=list;PROCESS_INFORMATION pi{};std::wstring cmd;for(auto&a:args){if(!cmd.empty())cmd+=L' ';cmd+=quote(a);}BOOL ok=CreateProcessW(args[0].c_str(),cmd.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi);DeleteProcThreadAttributeList(list);if(!ok)throw std::runtime_error("Cannot start media tool");proc.reset(pi.hProcess);CloseHandle(pi.hThread);
        watch=std::thread([this]{for(int i=0;i<6000&&!stop;i++)Sleep(100);if(!stop)TerminateProcess(proc.h,124);});
    }
    ~Child(){if(!done&&proc.h&&WaitForSingleObject(proc.h,0)==WAIT_TIMEOUT)TerminateProcess(proc.h,125);stop=true;if(watch.joinable())watch.join();}
    size_t get(void* data,size_t count){size_t got=0;while(got<count){DWORD n=0;if(!ReadFile(out.h,(char*)data+got,(DWORD)std::min<size_t>(count-got,1048576),&n,nullptr)||!n)break;got+=n;}return got;}
    void put(const void*data,size_t count){size_t sent=0;while(sent<count){DWORD n=0;if(!WriteFile(in.h,(char*)data+sent,(DWORD)std::min<size_t>(count-sent,1048576),&n,nullptr)||!n)throw std::runtime_error("Encoder write failed");sent+=n;}}
    std::string all(){std::string s;char b[8192];size_t n;while((n=get(b,sizeof b))){s.append(b,n);if(s.size()>8*1024*1024)throw std::runtime_error("Media tool output too large");}return s;}
    void finish(){in.reset();if(WaitForSingleObject(proc.h,60000)!=WAIT_OBJECT_0)throw std::runtime_error("Media tool timeout");DWORD c;GetExitCodeProcess(proc.h,&c);done=true;stop=true;if(c)throw std::runtime_error("Media tool failed (code "+std::to_string(c)+"); see job log");}
};
inline json probe(const fs::path& exe,const fs::path& input,const fs::path& dir){Child c({exe.wstring(),L"-v",L"error",L"-protocol_whitelist",L"file,pipe",L"-show_streams",L"-show_format",L"-of",L"json",input.wstring()},dir/L"probe.log");auto j=json::parse(c.all());c.finish();json v;for(auto&s:j["streams"])if(s.value("codec_type","")=="video"){v=s;break;}if(v.is_null())throw std::runtime_error("No video stream");double duration=std::stod(j["format"].value("duration","0"));if(!std::isfinite(duration)||duration<=0||duration>30.1)throw std::runtime_error("Demo supports videos up to 30 seconds");int w=v.value("width",0),h=v.value("height",0);if(w<32||h<32||w>8192||h>8192)throw std::runtime_error("Unsupported dimensions");return {{"width",w},{"height",h},{"duration",duration},{"codec",v.value("codec_name","")}};}
}
