#pragma once
// 재생 서버: 고른 영상을 이 PC의 웹 주소로 공개한다. 누군가 그 주소에서 재생하면 그 기기 전용 표식 사본을 만들어 재생시키고,
// 재생한 기기의 IP·브라우저·OS·시각을 data\issued.tsv에 기록한다. 영상에는 무작위 식별 번호만 들어가고 IP는 기록에만 남는다.
#include "forensic.h"

#include <ws2tcpip.h>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#pragma comment(lib, "ws2_32.lib")

namespace fm {

// ---------------------------------------------------------------- 아주 작은 HTTP (재생 서버·업로드 사이트 공용)
namespace http {

struct Request {
    std::string method, path, query, head, body_start;  // body_start: 헤더와 함께 받은 본문 앞부분
    std::string ip;
    std::string header(const std::string& name) const {
        std::string lower = head;
        for (char& ch : lower) ch = (char)tolower((unsigned char)ch);
        const size_t at = lower.find("\r\n" + name + ":");
        if (at == std::string::npos) return {};
        const size_t from = head.find_first_not_of(' ', at + name.size() + 3), end = head.find("\r\n", at + 2);
        return from < end ? head.substr(from, end - from) : std::string();
    }
};

inline bool read_request(SOCKET c, Request& r) {
    DWORD timeout = 15000;
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    std::string data;
    char buf[8192];
    size_t end;
    while ((end = data.find("\r\n\r\n")) == std::string::npos) {
        if (data.size() > 32768) return false;
        const int n = recv(c, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        data.append(buf, (size_t)n);
    }
    r.head = data.substr(0, end + 2);
    r.body_start = data.substr(end + 4);
    const size_t sp = r.head.find(' '), sp2 = r.head.find(' ', sp + 1);
    if (sp == std::string::npos || sp2 == std::string::npos) return false;
    r.method = r.head.substr(0, sp);
    const std::string target = r.head.substr(sp + 1, sp2 - sp - 1);
    const size_t q = target.find('?');
    r.path = target.substr(0, q);
    r.query = q == std::string::npos ? "" : target.substr(q + 1);
    return true;
}

inline std::string url_decode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            out += (char)std::stoi(s.substr(i + 1, 2), nullptr, 16);
            i += 2;
        } else {
            out += s[i] == '+' ? ' ' : s[i];
        }
    }
    return out;
}

inline std::string param(const std::string& query, const std::string& key) {
    std::istringstream s(query);
    for (std::string kv; std::getline(s, kv, '&');)
        if (kv.rfind(key + "=", 0) == 0) return url_decode(kv.substr(key.size() + 1));
    return {};
}

inline std::string json(const std::string& s) {
    std::string r = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') r += '\\', r += (char)c;
        else if (c == '\n') r += "\\n";
        else if (c < 0x20) r += ' ';
        else r += (char)c;
    }
    return r + "\"";
}

inline bool send_all(SOCKET c, const char* d, size_t n) {
    while (n) {
        const int k = send(c, d, (int)std::min<size_t>(n, 1 << 20), 0);
        if (k <= 0) return false;
        d += k;
        n -= (size_t)k;
    }
    return true;
}

// 같은 PC에서 파일로 연 페이지도 부를 수 있게 모든 응답에 CORS 허용을 붙인다
constexpr const char* CORS = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n";

inline void reply(SOCKET c, const char* status, const char* type, const std::string& body) {
    const std::string head = std::string("HTTP/1.1 ") + status + "\r\nContent-Type: " + type + "\r\nContent-Length: " +
                             std::to_string(body.size()) + "\r\nCache-Control: no-store\r\n" + CORS + "Connection: close\r\n\r\n";
    send_all(c, head.data(), head.size()) && send_all(c, body.data(), body.size());
}

// 파일 보내기. Range 요청(영상 앞뒤로 넘기기)을 지원한다
inline void send_file(SOCKET c, const fs::path& file, const std::string& range, const char* type) {
    std::ifstream f(file, std::ios::binary);
    if (!f) {
        reply(c, "404 Not Found", "text/plain", "");
        return;
    }
    const uint64_t total = fs::file_size(file);
    uint64_t from = 0, to = total ? total - 1 : 0;
    const bool partial = range.rfind("bytes=", 0) == 0;
    if (partial) {
        const size_t dash = range.find('-');
        try {
            if (dash > 6) from = std::stoull(range.substr(6, dash - 6));
            if (dash != std::string::npos && dash + 1 < range.size()) to = std::min(to, (uint64_t)std::stoull(range.substr(dash + 1)));
        } catch (...) {
        }
        if (from > to) {
            reply(c, "416 Range Not Satisfiable", "text/plain", "");
            return;
        }
    }
    std::string head = std::string("HTTP/1.1 ") + (partial ? "206 Partial Content" : "200 OK") + "\r\nContent-Type: " + type +
                       "\r\nAccept-Ranges: bytes\r\nContent-Length: " + std::to_string(total ? to - from + 1 : 0) + "\r\nCache-Control: no-store\r\n" +
                       CORS + "Connection: close\r\n";
    if (partial) head += "Content-Range: bytes " + std::to_string(from) + "-" + std::to_string(to) + "/" + std::to_string(total) + "\r\n";
    head += "\r\n";
    if (!send_all(c, head.data(), head.size()) || !total) return;
    f.seekg((std::streamoff)from);
    std::vector<char> buf(1 << 16);
    for (uint64_t left = to - from + 1; left && f;) {
        f.read(buf.data(), (std::streamsize)std::min<uint64_t>(left, buf.size()));
        const size_t got = (size_t)f.gcount();
        if (!got || !send_all(c, buf.data(), got)) break;
        left -= got;
    }
}

// 0.0.0.0의 port~port+19 중 빈 포트를 열고, 연결마다 handler를 새 스레드에서 부른다
class Listener {
public:
    using Handler = std::function<void(SOCKET, const std::string& ip)>;
    ~Listener() { stop(); }
    int start(int port, Handler handler) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) throw std::runtime_error("네트워크를 사용할 수 없어요");
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL one = TRUE;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        int p = port;
        for (; p < port + 20; ++p) {
            a.sin_port = htons((u_short)p);
            if (bind(s, (sockaddr*)&a, sizeof(a)) == 0) break;
        }
        if (p == port + 20 || listen(s, SOMAXCONN) != 0) {
            closesocket(s);
            throw std::runtime_error(std::to_string(port) + "~" + std::to_string(port + 19) + "번 포트를 열 수 없어요");
        }
        sock_ = s;
        thread_ = std::thread([s, handler] {
            for (;;) {
                sockaddr_in ca{};
                int len = sizeof(ca);
                const SOCKET c = accept(s, (sockaddr*)&ca, &len);
                if (c == INVALID_SOCKET) break;  // stop()에서 소켓을 닫으면 끝난다
                char ip[INET_ADDRSTRLEN] = "";
                inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
                std::thread([c, handler, address = std::string(ip)] {
                    try {
                        handler(c, address);
                    } catch (...) {
                    }
                    shutdown(c, SD_SEND);
                    closesocket(c);
                }).detach();
            }
        });
        return p;
    }
    void stop() {
        if (sock_ == INVALID_SOCKET) return;
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
        if (thread_.joinable()) thread_.join();
    }
    bool running() const { return sock_ != INVALID_SOCKET; }

private:
    SOCKET sock_ = INVALID_SOCKET;
    std::thread thread_;
};

}  // namespace http

// User-Agent에서 OS와 브라우저 이름만 뽑는다 (예: "Android · Chrome")
inline std::string device_of(const std::string& ua) {
    auto has = [&](const char* s) { return ua.find(s) != std::string::npos; };
    const std::string os = has("Android") ? "Android" : has("iPhone") ? "iPhone" : has("iPad") ? "iPad" : has("Windows") ? "Windows"
                           : has("Mac OS X") ? "macOS" : has("Linux") ? "Linux" : "알 수 없는 OS";
    const std::string browser = has("KAKAOTALK") ? "카카오톡" : has("Edg") ? "Edge" : has("SamsungBrowser") ? "삼성 인터넷" : has("Whale") ? "웨일"
                                : has("OPR/") ? "Opera" : has("Firefox/") || has("FxiOS") ? "Firefox" : has("Chrome/") || has("CriOS") ? "Chrome"
                                : has("Safari/") ? "Safari" : ua.empty() ? "알 수 없는 앱" : ua.substr(0, std::min<size_t>(ua.find(' '), 24));
    return os + " · " + browser;
}

class PlayServer {
public:
    using Notify = std::function<void()>;  // 기록이 늘었을 때 (서버 스레드에서 호출)

    ~PlayServer() { stop(); }

    // 영상을 등록하고 8080번(사용 중이면 8099번까지) 포트를 연다. 반환: 접속 주소
    std::string start(const Paths& p, const fs::path& video, Notify notify) {
        stop();
        auto st = std::make_shared<State>();
        st->p = p;
        st->video = fs::absolute(video);
        st->asset = register_asset(p, video);
        st->notify = std::move(notify);
        const int port = listener_.start(8080, [st](SOCKET c, const std::string& ip) { handle(st, c, ip); });
        state_ = st;
        address_ = "http://" + local_ipv4() + ":" + std::to_string(port) + "/";
        return address_;
    }

    void stop() {
        listener_.stop();
        state_.reset();
    }

    bool running() const { return listener_.running(); }
    const std::string& address() const { return address_; }
    std::string asset_id() const { return state_ ? state_->asset.id : ""; }

    // 지금까지 재생한 기기 수, 사본을 만드는 중인 기기 수
    std::pair<int, int> counts() const {
        if (!state_) return {0, 0};
        std::lock_guard<std::mutex> l(state_->m);
        int ready = 0, wait = 0;
        for (const auto& [k, v] : state_->viewers) {
            if (v.state == "ready") ++ready;
            else if (v.state == "wait") ++wait;
        }
        return {ready, wait};
    }

private:
    struct Viewer {
        std::string state = "wait";  // wait | ready | error
        fs::path file;
    };
    struct State {
        Paths p;
        Asset asset;
        fs::path video;
        Notify notify;
        mutable std::mutex m;                   // viewers 보호
        std::mutex work;                        // 사본은 한 번에 하나씩 만든다 (기록 파일 동시 쓰기 방지)
        std::map<std::string, Viewer> viewers;  // 키: IP + User-Agent (같은 기기가 다시 열면 같은 사본)
    };

    // 이 기기의 사본 상태. 처음 온 기기면 사본 만들기를 시작한다
    static std::string prepare(const std::shared_ptr<State>& st, const std::string& ip, const std::string& ua) {
        const std::string key = ip + "|" + ua;
        {
            std::lock_guard<std::mutex> l(st->m);
            const auto it = st->viewers.find(key);
            if (it != st->viewers.end()) return it->second.state;
            st->viewers[key] = {};
        }
        std::thread([st, key, ip, ua] {
            Viewer v;
            try {
                std::lock_guard<std::mutex> w(st->work);
                const Issue i = issue_copy(st->p, st->asset.id, ua, device_of(ua), ip, {}, st->video, st->p.issued);
                v = {"ready", wide(i.file)};
            } catch (...) {
                v.state = "error";
            }
            {
                std::lock_guard<std::mutex> l(st->m);
                st->viewers[key] = v;
            }
            if (st->notify) st->notify();
        }).detach();
        if (st->notify) st->notify();
        return "wait";
    }

    static void handle(const std::shared_ptr<State>& st, SOCKET c, const std::string& ip) {
        http::Request req;
        if (!http::read_request(c, req)) return;
        const std::string ua = req.header("user-agent");
        if (req.path == "/") {
            http::reply(c, "200 OK", "text/html; charset=utf-8", page());
        } else if (req.path == "/ready") {
            http::reply(c, "200 OK", "text/plain", prepare(st, ip, ua));
        } else if (req.path == "/video.mp4") {
            fs::path file;
            {
                std::lock_guard<std::mutex> l(st->m);
                const auto it = st->viewers.find(ip + "|" + ua);
                if (it != st->viewers.end() && it->second.state == "ready") file = it->second.file;
            }
            if (file.empty()) http::reply(c, "404 Not Found", "text/plain", "not ready");
            else http::send_file(c, file, req.header("range"), "video/mp4");
        } else {
            http::reply(c, "404 Not Found", "text/plain", "");
        }
    }

    static std::string page() {
        return R"(<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>영상 재생</title><style>
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;background:#11161d;color:#e8eef2;font-family:system-ui,"Malgun Gothic",sans-serif}
video{width:min(960px,100vw);max-height:80vh;background:#000}p{margin:0;padding:0 16px;color:#96a6b2;font-size:14px;text-align:center}</style></head>
<body><video id="v" controls playsinline hidden></video><p id="s">이 기기에서 볼 영상을 준비하고 있어요…</p>
<p>이 영상에는 시청 기록을 위한 보이지 않는 표식이 들어 있습니다.</p>
<script>
async function poll(){
  let t='wait';
  try{t=await (await fetch('/ready',{cache:'no-store'})).text();}catch(e){}
  if(t==='ready'){const v=document.getElementById('v');v.src='/video.mp4';v.hidden=false;document.getElementById('s').hidden=true;}
  else if(t==='error'){document.getElementById('s').textContent='영상을 준비하지 못했어요';}
  else setTimeout(poll,1000);
}
poll();
</script></body></html>)";
    }

    http::Listener listener_;
    std::shared_ptr<State> state_;
    std::string address_;
};

}  // namespace fm
