#pragma once
// ForensicMark 핵심 기능: 영상마다 '고유 코드', 받는 사람마다 '개별 식별 번호'를 보이지 않게 넣고, 유출본에서 다시 찾는다.
// 영상에는 무작위 번호만 들어간다. 누가·어떤 기기·어떤 IP로 받았는지는 data\issued.tsv에만 기록한다.
// 워터마크는 VideoShield v2에서 검증한 DCT 방식이며, wm 네임스페이스만 바꾸면 VideoSeal 등으로 교체할 수 있다.
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <algorithm>
#include <bitset>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace fm {
namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;

// ---------------------------------------------------------------- 문자열

inline std::string utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

inline std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

inline std::string hex(uint64_t v, int digits) {
    std::ostringstream s;
    s << std::hex << std::setw(digits) << std::setfill('0') << v;
    return s.str();
}

inline std::string now_text() {
    SYSTEMTIME t;
    GetLocalTime(&t);
    char b[32];
    sprintf_s(b, "%04d-%02d-%02d %02d:%02d:%02d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    return b;
}

// 기록 파일(TSV)에 넣을 수 있게 탭·줄바꿈을 공백으로
inline std::string clean(std::string s) {
    for (char& c : s)
        if (c == '\t' || c == '\r' || c == '\n') c = ' ';
    return s;
}

// ---------------------------------------------------------------- 이 PC 정보 (기기·IP 기본값)

inline std::string computer_name() {
    wchar_t b[256];
    DWORD n = 256;
    return GetComputerNameExW(ComputerNameDnsHostname, b, &n) ? utf8(b) : "unknown";
}

// 이 PC의 IPv4 주소 (공유기 안쪽 주소). 인터넷 쪽 공인 IP는 외부 서비스에 물어봐야 해서 쓰지 않는다
inline std::string local_ipv4() {
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf(size);
    const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    }
    if (rc != NO_ERROR) return "unknown";
    std::string fallback;
    for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            const auto* b = (const unsigned char*)&((const sockaddr_in*)u->Address.lpSockaddr)->sin_addr;
            const std::string ip = std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) + "." + std::to_string(b[3]);
            if (a->FirstGatewayAddress) return ip;  // 실제로 바깥과 연결된 어댑터를 우선
            if (fallback.empty()) fallback = ip;
        }
    }
    return fallback.empty() ? "unknown" : fallback;
}

// ---------------------------------------------------------------- 경로·설정

struct Paths {
    fs::path home, data, issued;
    std::wstring ffmpeg, ffprobe;
};

inline Paths paths() {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    Paths p;
    p.home = fs::path(exe).parent_path();
    p.data = p.home / L"data";
    p.issued = p.home / L"issued";
    const std::wstring ini = (p.home / L"settings.ini").wstring();
    wchar_t v[1024];
    GetPrivateProfileStringW(L"runtime", L"ffmpeg", L"ffmpeg", v, 1024, ini.c_str());
    p.ffmpeg = v;
    GetPrivateProfileStringW(L"runtime", L"ffprobe", L"ffprobe", v, 1024, ini.c_str());
    p.ffprobe = v;
    return p;
}

// ---------------------------------------------------------------- 암호 (Windows CNG)

inline Bytes read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("파일을 열 수 없어요: " + utf8(path.wstring()));
    return Bytes(std::istreambuf_iterator<char>(f), {});
}

inline Bytes random_bytes(size_t n) {
    Bytes b(n);
    if (BCryptGenRandom(nullptr, b.data(), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("난수 생성 실패");
    return b;
}

inline Bytes hash(const Bytes& key, const Bytes& data) {  // key가 비어 있으면 SHA-256, 있으면 HMAC-SHA256
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, key.empty() ? 0 : BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        throw std::runtime_error("SHA-256을 사용할 수 없어요");
    Bytes out(32);
    const NTSTATUS st = BCryptHash(alg, key.empty() ? nullptr : (PUCHAR)key.data(), (ULONG)key.size(),
                                   (PUCHAR)data.data(), (ULONG)data.size(), out.data(), (ULONG)out.size());
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) throw std::runtime_error("해시 계산 실패");
    return out;
}

// 비밀키: data\secret.key (처음 실행할 때 생성). 표식을 만들고 검증하려면 같은 키가 필요하다. 공유 저장소에 올리지 말 것.
inline Bytes secret_key(const Paths& p) {
    const fs::path file = p.data / L"secret.key";
    if (!fs::exists(file)) {
        fs::create_directories(p.data);
        const Bytes k = random_bytes(32);
        std::ofstream(file, std::ios::binary).write((const char*)k.data(), (std::streamsize)k.size());
    }
    Bytes k = read_file(file);
    if (k.size() != 32) throw std::runtime_error("data\\secret.key가 손상됐어요");
    return k;
}

// ---------------------------------------------------------------- 메시지 (64비트)
// [영상 고유 코드 16비트][개별 식별 번호 24비트][위조 방지값 24비트 = HMAC-SHA256(비밀키, 앞 40비트) 앞부분]
// 위조 방지값 덕분에 비밀키 없이는 다른 사람의 번호를 만들어 넣을 수 없고, 깨진 번호를 엉뚱한 사람으로 읽지도 않는다.

constexpr int BITS = 64;

inline uint32_t tag24(const Bytes& key, uint32_t asset, uint32_t viewer) {
    const Bytes d{'F', 'M', '1', (unsigned char)(asset >> 8), (unsigned char)asset, (unsigned char)(viewer >> 16),
                  (unsigned char)(viewer >> 8), (unsigned char)viewer};
    const Bytes h = hash(key, d);
    return ((uint32_t)h[0] << 16) | ((uint32_t)h[1] << 8) | h[2];
}

inline uint64_t make_message(const Bytes& key, uint32_t asset, uint32_t viewer) {
    return ((uint64_t)(asset & 0xFFFF) << 48) | ((uint64_t)(viewer & 0xFFFFFF) << 24) | tag24(key, asset, viewer);
}

// ---------------------------------------------------------------- DCT 워터마크 (VideoShield v2에서 검증한 설정)
// 화면을 640×360 기준 해상도로 줄여 8×8 블록 3600개로 나누고, 블록마다 낮은 중간 주파수 계수 (1,2)와 (2,1)의
// 크기 관계로 비트 하나를 표시한다. 비트마다 키로 섞은 블록 56개 이상에 반복하고, 모든 블록·프레임을 합쳐 읽는다.
// 측정: CRF 23·30 재압축, 480p 축소, 일부 구간 추출에서 검출. 가장자리 잘라내기에는 약하다.

namespace wm {
constexpr int CW = 640, CH = 360, BS = 8, BX = CW / BS, BY = CH / BS, BLOCKS = BX * BY;
constexpr int U1 = 1, V1 = 2, U2 = 2, V2 = 1;
constexpr float T_MIN = 6.f, T_MAX = 14.f;  // 계수 차이 목표. 평평한 블록은 약하게, 복잡한 블록은 강하게
constexpr float NEED_MAX = 8.f;             // 블록당 변경 상한 (픽셀 변화 약 ±4)
constexpr float CLIP = 10.f;                // 읽을 때 블록 하나의 영향 상한

struct Basis {
    float c[BS][BS];
    Basis() {
        for (int u = 0; u < BS; ++u)
            for (int x = 0; x < BS; ++x)
                c[u][x] = (float)((u == 0 ? std::sqrt(1.0 / BS) : std::sqrt(2.0 / BS)) *
                                  std::cos((2 * x + 1) * u * 3.14159265358979 / (2 * BS)));
    }
};
inline const Basis& basis() {
    static const Basis b;
    return b;
}

inline std::vector<int> layout(const Bytes& key) {  // 블록마다 담당 비트를 비밀키로 섞어 정한다
    const Bytes seed = hash(key, Bytes{'l', 'a', 'y', 'o', 'u', 't'});
    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s = (s << 8) | seed[i];
    std::vector<int> order(BLOCKS), owner(BLOCKS);
    std::iota(order.begin(), order.end(), 0);
    std::mt19937_64 rng(s);
    std::shuffle(order.begin(), order.end(), rng);
    for (int i = 0; i < BLOCKS; ++i) owner[order[i]] = i % BITS;
    return owner;
}

inline std::vector<float> resize_plane(const std::vector<float>& src, int sw, int sh, int dw, int dh) {
    std::vector<float> dst((size_t)dw * dh);
    for (int y = 0; y < dh; ++y) {
        const float fy = (y + 0.5f) * sh / dh - 0.5f;
        const int y0 = std::clamp((int)std::floor(fy), 0, sh - 1), y1 = std::min(y0 + 1, sh - 1);
        const float wy = std::clamp(fy - y0, 0.f, 1.f);
        for (int x = 0; x < dw; ++x) {
            const float fx = (x + 0.5f) * sw / dw - 0.5f;
            const int x0 = std::clamp((int)std::floor(fx), 0, sw - 1), x1 = std::min(x0 + 1, sw - 1);
            const float wx = std::clamp(fx - x0, 0.f, 1.f);
            dst[(size_t)y * dw + x] = (src[(size_t)y0 * sw + x0] * (1 - wx) + src[(size_t)y0 * sw + x1] * wx) * (1 - wy) +
                                      (src[(size_t)y1 * sw + x0] * (1 - wx) + src[(size_t)y1 * sw + x1] * wx) * wy;
        }
    }
    return dst;
}

inline float coeff(const std::vector<float>& y, int bx, int by, int u, int v) {
    const Basis& B = basis();
    float s = 0;
    for (int i = 0; i < BS; ++i)
        for (int j = 0; j < BS; ++j) s += B.c[u][i] * B.c[v][j] * y[(size_t)(by * BS + i) * CW + bx * BS + j];
    return s;
}

inline void embed(unsigned char* rgb, int w, int h, uint64_t message, const std::vector<int>& owner) {
    const Basis& B = basis();
    std::vector<float> lum((size_t)w * h);
    for (size_t k = 0; k < lum.size(); ++k) lum[k] = 0.299f * rgb[k * 3] + 0.587f * rgb[k * 3 + 1] + 0.114f * rgb[k * 3 + 2];
    const auto y = resize_plane(lum, w, h, CW, CH);
    std::vector<float> delta((size_t)CW * CH, 0.f);
    for (int by = 0; by < BY; ++by)
        for (int bx = 0; bx < BX; ++bx) {
            const float s = (message >> (BITS - 1 - owner[by * BX + bx])) & 1 ? 1.f : -1.f;
            float mean = 0, var = 0;
            for (int i = 0; i < BS; ++i)
                for (int j = 0; j < BS; ++j) mean += y[(size_t)(by * BS + i) * CW + bx * BS + j];
            mean /= BS * BS;
            for (int i = 0; i < BS; ++i)
                for (int j = 0; j < BS; ++j) {
                    const float d = y[(size_t)(by * BS + i) * CW + bx * BS + j] - mean;
                    var += d * d;
                }
            const float target = T_MIN + (T_MAX - T_MIN) * std::clamp(std::sqrt(var / (BS * BS)) / 20.f, 0.f, 1.f);
            const float d = coeff(y, bx, by, U1, V1) - coeff(y, bx, by, U2, V2);
            if (s * d >= target) continue;
            const float need = std::min((target - s * d) / 2, NEED_MAX);
            for (int i = 0; i < BS; ++i)
                for (int j = 0; j < BS; ++j)
                    delta[(size_t)(by * BS + i) * CW + bx * BS + j] += s * need * (B.c[U1][i] * B.c[V1][j] - B.c[U2][i] * B.c[V2][j]);
        }
    const auto full = resize_plane(delta, CW, CH, w, h);
    for (size_t k = 0; k < full.size(); ++k)
        for (int c = 0; c < 3; ++c) {
            unsigned char& v = rgb[k * 3 + c];
            v = (unsigned char)std::clamp((int)std::lround(v + full[k]), 0, 255);
        }
}

inline void accumulate(const std::vector<float>& y, const std::vector<int>& owner, std::vector<double>& soft) {
    for (int by = 0; by < BY; ++by)
        for (int bx = 0; bx < BX; ++bx)
            soft[owner[by * BX + bx]] += std::clamp(coeff(y, bx, by, U1, V1) - coeff(y, bx, by, U2, V2), -CLIP, CLIP);
}

// 두 계수의 차이를 한 번에 계산하는 8×8 가중치 (가공 추정 때 빠르게 쓰기 위함)
struct Kernel {
    float k[BS][BS];
    Kernel() {
        const Basis& B = basis();
        for (int i = 0; i < BS; ++i)
            for (int j = 0; j < BS; ++j) k[i][j] = B.c[U1][i] * B.c[V1][j] - B.c[U2][i] * B.c[V2][j];
    }
};
inline const Kernel& kernel() {
    static const Kernel k;
    return k;
}
}  // namespace wm

// ---------------------------------------------------------------- ffmpeg 프로세스 (창 없이 실행, 파이프로 프레임 주고받기)

inline std::wstring quoted(const std::wstring& s) { return L"\"" + s + L"\""; }

class Process {
public:
    // reading=true: 자식의 표준 출력을 읽는다 / false: 자식의 표준 입력에 쓴다. 오류 메시지는 data\ffmpeg.log
    Process(std::wstring cmd, bool reading, const fs::path& log) {
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE rd = nullptr, wr = nullptr;
        if (!CreatePipe(&rd, &wr, &sa, 1 << 20)) throw std::runtime_error("파이프 생성 실패");
        mine_ = reading ? rd : wr;
        HANDLE child = reading ? wr : rd;
        SetHandleInformation(mine_, HANDLE_FLAG_INHERIT, 0);
        fs::create_directories(log.parent_path());
        HANDLE err = CreateFileW(log.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_ALWAYS, 0, nullptr);
        HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = reading ? nul : child;
        si.hStdOutput = reading ? child : nul;
        si.hStdError = err;
        const BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi_);
        CloseHandle(child);
        CloseHandle(nul);
        CloseHandle(err);
        if (!ok) {
            CloseHandle(mine_);
            mine_ = nullptr;
            throw std::runtime_error("ffmpeg를 실행할 수 없어요. settings.ini의 경로를 확인하세요");
        }
    }
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    ~Process() {
        if (pi_.hProcess) finish();
    }

    size_t read(void* buf, size_t n) {  // n바이트를 다 채우거나 끝에 도달할 때까지 읽는다
        size_t total = 0;
        while (total < n) {
            DWORD got = 0;
            if (!ReadFile(mine_, (char*)buf + total, (DWORD)std::min<size_t>(n - total, 1 << 20), &got, nullptr) || !got) break;
            total += got;
        }
        return total;
    }

    bool write(const void* buf, size_t n) {
        size_t total = 0;
        while (total < n) {
            DWORD put = 0;
            if (!WriteFile(mine_, (const char*)buf + total, (DWORD)std::min<size_t>(n - total, 1 << 20), &put, nullptr)) return false;
            total += put;
        }
        return true;
    }

    int finish() {
        if (mine_) {
            CloseHandle(mine_);
            mine_ = nullptr;
        }
        WaitForSingleObject(pi_.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(pi_.hProcess, &code);
        CloseHandle(pi_.hProcess);
        CloseHandle(pi_.hThread);
        pi_ = {};
        return (int)code;
    }

private:
    HANDLE mine_ = nullptr;
    PROCESS_INFORMATION pi_{};
};

struct VideoInfo {
    int w = 0, h = 0;
    std::wstring rate;  // ffprobe의 r_frame_rate 그대로 (예: 30/1)
};

inline VideoInfo probe(const Paths& p, const fs::path& video, bool need_even = true) {
    Process proc(quoted(p.ffprobe) + L" -v error -select_streams v:0 -show_entries stream=width,height,r_frame_rate -of csv=p=0 " +
                     quoted(video.wstring()),
                 true, p.data / L"ffmpeg.log");
    std::string out(256, '\0');
    out.resize(proc.read(out.data(), out.size()));
    proc.finish();
    VideoInfo info;
    std::istringstream s(out);
    std::string w, h, rate;
    std::getline(s, w, ',');
    std::getline(s, h, ',');
    std::getline(s, rate);
    while (!rate.empty() && (rate.back() == '\r' || rate.back() == '\n' || rate.back() == ' ')) rate.pop_back();
    try {
        info.w = std::stoi(w);
        info.h = std::stoi(h);
    } catch (...) {
        throw std::runtime_error("영상 정보를 읽을 수 없어요: " + utf8(video.wstring()));
    }
    info.rate = wide(rate.empty() ? "30/1" : rate);
    if (need_even && (info.w % 2 || info.h % 2)) throw std::runtime_error("가로·세로 크기가 짝수인 영상만 지원해요");
    return info;
}

inline double fps_of(const std::wstring& rate) {
    const std::string r = utf8(rate);
    const size_t slash = r.find('/');
    try {
        return slash == std::string::npos ? std::stod(r) : std::stod(r.substr(0, slash)) / std::max(1.0, std::stod(r.substr(slash + 1)));
    } catch (...) {
        return 30;
    }
}

// 진행률 표시용 전체 프레임 수 추정 (길이 × fps). 알 수 없으면 0
inline int estimate_frames(const Paths& p, const fs::path& video) {
    try {
        Process proc(quoted(p.ffprobe) + L" -v error -show_entries format=duration -of csv=p=0 " + quoted(video.wstring()), true,
                     p.data / L"ffmpeg.log");
        std::string out(64, '\0');
        out.resize(proc.read(out.data(), out.size()));
        proc.finish();
        return (int)std::lround(std::stod(out) * fps_of(probe(p, video).rate));
    } catch (...) {
        return 0;
    }
}

using Progress = std::function<void(int frames)>;

// 원본 영상의 모든 프레임에 메시지를 넣어 새 MP4로 저장한다 (오디오 유지, 원본은 건드리지 않음)
inline int mark_video(const Paths& p, const fs::path& src, const fs::path& dst, uint64_t message, const std::vector<int>& owner,
                      const Progress& progress = {}) {
    const VideoInfo info = probe(p, src);
    const fs::path log = p.data / L"ffmpeg.log";
    Process dec(quoted(p.ffmpeg) + L" -v error -i " + quoted(src.wstring()) + L" -f rawvideo -pix_fmt rgb24 -", true, log);
    Process enc(quoted(p.ffmpeg) + L" -v error -y -f rawvideo -pix_fmt rgb24 -s " + std::to_wstring(info.w) + L"x" +
                    std::to_wstring(info.h) + L" -r " + info.rate + L" -i - -i " + quoted(src.wstring()) +
                    L" -map 0:v -map 1:a? -c:v libx264 -preset fast -crf 18 -pix_fmt yuv420p -c:a aac -b:a 128k -shortest -movflags +faststart " +
                    quoted(dst.wstring()),
                false, log);
    std::vector<unsigned char> frame((size_t)info.w * info.h * 3);
    int count = 0;
    while (dec.read(frame.data(), frame.size()) == frame.size()) {
        wm::embed(frame.data(), info.w, info.h, message, owner);
        if (!enc.write(frame.data(), frame.size())) break;
        if (progress) progress(++count);
        else ++count;
    }
    dec.finish();
    if (enc.finish() != 0 || count == 0) throw std::runtime_error("표식 영상 저장 실패 (data\\ffmpeg.log 참고)");
    return count;
}

// ---------------------------------------------------------------- 검출

// 가공 추정: 원본 화면이 의심 영상 안에 어떻게 놓였는지 (반전·잘라내기·회전·검은 띠)
struct Geometry {
    bool hflip = false, vflip = false, bars = false;  // bars: 검은 띠를 걷어내고 읽었는지
    float x0 = 0, x1 = 1, y0 = 0, y1 = 1;             // 의심 영상(검은 띠 제외)에 보이는 원본 화면의 범위 (0~1)
    float angle = 0;                                  // 회전 (도)
};

// 되돌린 가공을 하나씩 (가공이 없으면 빈 목록)
inline std::vector<std::string> edit_list(const Geometry& g) {
    std::vector<std::string> out;
    auto add = [&](const std::string& part) { out.push_back(part); };
    if (g.bars) add("검은 띠");
    if (g.hflip) add("좌우 반전");
    if (g.vflip) add("상하 반전");
    const float cut = 100.f * (1 - std::min(g.x1 - g.x0, g.y1 - g.y0));  // 가로·세로 중 더 많이 잘린 쪽
    if (cut >= 1.f) {
        char b[48];
        sprintf_s(b, "가장자리 약 %.0f%% 잘림", cut);
        add(b);
    }
    if (std::abs(g.angle) >= 0.25f) {
        char b[32];
        sprintf_s(b, "%.1f도 회전", std::abs(g.angle));
        add(b);
    }
    return out;
}

inline std::string describe(const Geometry& g) {
    std::string s;
    for (const auto& part : edit_list(g)) s += (s.empty() ? "" : " · ") + part;
    return s.empty() ? "크기·비율 변경 또는 재압축" : s;
}

struct Detection {
    bool verified = false;  // 위조 방지값까지 맞는 번호를 찾았는지
    uint32_t asset = 0, viewer = 0;
    int frames = 0, corrected_bits = 0;
    double margin = 0;  // 비트당 평균 신호 크기 (표식 없는 영상은 보통 20 이하)
    bool transformed = false;  // 가공을 되돌려서 읽었는지
    Geometry geometry;
    std::vector<double> soft;  // 비트별 신호 (부호가 비트 값, 크기가 확신 정도)
};

// 비트별 신호에서 번호를 읽는다. 확신이 가장 낮은 비트 10개 중 max_flips개까지 뒤집어 보며 위조 방지값이 맞는 조합을 찾는다.
// 잘못 맞출 확률은 3개일 때 약 176 / 2^24 (≈ 0.001%)
inline bool decode_soft(const std::vector<double>& soft, const Bytes& key, int max_flips, Detection& r) {
    uint64_t hard = 0;
    for (double s : soft) hard = (hard << 1) | (s > 0 ? 1u : 0u);
    std::vector<int> weakest(BITS);
    std::iota(weakest.begin(), weakest.end(), 0);
    std::sort(weakest.begin(), weakest.end(), [&](int a, int b) { return std::abs(soft[a]) < std::abs(soft[b]); });
    for (int flips = 0; flips <= max_flips; ++flips)
        for (unsigned mask = 0; mask < (1u << 10); ++mask) {
            if ((int)std::bitset<10>(mask).count() != flips) continue;
            uint64_t m = hard;
            for (int i = 0; i < 10; ++i)
                if (mask >> i & 1) m ^= 1ull << (BITS - 1 - weakest[i]);
            const uint32_t asset = (uint32_t)(m >> 48), viewer = (uint32_t)(m >> 24) & 0xFFFFFF, tag = (uint32_t)m & 0xFFFFFF;
            if (tag24(key, asset, viewer) == tag) {
                r.verified = true;
                r.asset = asset;
                r.viewer = viewer;
                r.corrected_bits = flips;
                return true;
            }
        }
    return false;
}

// 의심 영상을 가로 640 기준(비율 유지)으로 읽은 결과
struct Frames {
    int w = 0, h = 0, count = 0;
    std::vector<float> mean;                 // 모든 프레임의 평균 밝기: 표식은 매 프레임 같은 자리에 있어 남고, 내용·압축 잡음은 흐려진다
    std::vector<unsigned char> peak;         // 픽셀별 최댓값 (검은 띠 찾기)
    int tw = 0, th = 0;                      // 축소본 크기 (4분의 1)
    std::vector<std::vector<float>> thumbs;  // 초당 약 4장 (지문용)
    std::vector<float> times;                // 각 축소본의 영상 속 시각 (초)
    double fps = 30;
};

inline Frames read_frames(const Paths& p, const fs::path& video, int max_frames) {
    const VideoInfo info = probe(p, video, false);
    Frames f;
    f.w = 640;
    f.h = std::max(8, (int)std::lround(640.0 * info.h / info.w / 2) * 2);
    f.tw = f.w / 4;
    f.th = f.h / 4;
    f.fps = fps_of(info.rate);
    const int stride = std::max(1, (int)std::lround(f.fps / 4));
    Process dec(quoted(p.ffmpeg) + L" -v error -i " + quoted(video.wstring()) + L" -an -vf scale=640:" + std::to_wstring(f.h) +
                    L":flags=area -pix_fmt gray -f rawvideo -",
                true, p.data / L"ffmpeg.log");
    std::vector<unsigned char> buf((size_t)f.w * f.h);
    std::vector<double> sum(buf.size(), 0.0);
    f.peak.assign(buf.size(), 0);
    while ((max_frames <= 0 || f.count < max_frames) && dec.read(buf.data(), buf.size()) == buf.size()) {
        for (size_t k = 0; k < buf.size(); ++k) {
            sum[k] += buf[k];
            f.peak[k] = std::max(f.peak[k], buf[k]);
        }
        if (f.count % stride == 0) {
            std::vector<float> t((size_t)f.tw * f.th, 0.f);
            for (int y = 0; y < f.th * 4; ++y)
                for (int x = 0; x < f.tw * 4; ++x) t[(size_t)(y / 4) * f.tw + x / 4] += buf[(size_t)y * f.w + x] / 16.f;
            f.thumbs.push_back(std::move(t));
            f.times.push_back((float)(f.count / f.fps));
        }
        ++f.count;
    }
    dec.finish();
    if (!f.count) throw std::runtime_error("영상을 읽을 수 없어요: " + utf8(video.wstring()));
    f.mean.resize(buf.size());
    for (size_t k = 0; k < buf.size(); ++k) f.mean[k] = (float)(sum[k] / f.count);
    return f;
}

struct Box {
    int x = 0, y = 0, w = 0, h = 0;
};

// 영상 내내 어두운 위·아래·좌·우 줄을 검은 띠로 보고 걷어낸 화면 영역
inline Box content_box(const Frames& f) {
    constexpr unsigned char DARK = 40;
    auto row_dark = [&](int r) {
        for (int x = 0; x < f.w; ++x)
            if (f.peak[(size_t)r * f.w + x] > DARK) return false;
        return true;
    };
    auto col_dark = [&](int c) {
        for (int y = 0; y < f.h; ++y)
            if (f.peak[(size_t)y * f.w + c] > DARK) return false;
        return true;
    };
    int top = 0, bottom = f.h, left = 0, right = f.w;
    while (top < f.h && row_dark(top)) ++top;
    while (bottom > top && row_dark(bottom - 1)) --bottom;
    while (left < f.w && col_dark(left)) ++left;
    while (right > left && col_dark(right - 1)) --right;
    if (bottom - top < f.h / 4 || right - left < f.w / 4) return {0, 0, f.w, f.h};  // 거의 전부 어두운 영상은 띠로 보지 않는다
    return {left, top, right - left, bottom - top};
}

inline float bilinear(const std::vector<float>& img, int w, int h, float x, float y) {
    x = std::clamp(x, 0.f, (float)w - 1);
    y = std::clamp(y, 0.f, (float)h - 1);
    const int x0 = std::min((int)x, w - 2), y0 = std::min((int)y, h - 2);
    const float ax = x - x0, ay = y - y0;
    const float* r0 = &img[(size_t)y0 * w + x0];
    const float* r1 = r0 + w;
    return (r0[0] * (1 - ax) + r0[1] * ax) * (1 - ay) + (r1[0] * (1 - ax) + r1[1] * ax) * ay;
}

// 가정한 배치(g)대로 평균 화면에서 기준 해상도(640×360)의 블록을 다시 뽑아 비트별 신호를 더한다.
// 영상 밖으로 나간 블록은 건너뛴다. 반환값은 표식이 얼마나 뚜렷한지 (클수록 배치가 맞음)
inline double score_layout(const Frames& f, const Box& b, const Geometry& g, const std::vector<int>& owner, std::vector<double>& soft) {
    using namespace wm;
    const auto& K = kernel().k;
    soft.assign(BITS, 0.0);
    int n[BITS] = {};
    const float rad = g.angle * 3.14159265f / 180.f, c = std::cos(rad), s = std::sin(rad);
    const float sx = 1.f / (g.x1 - g.x0), sy = 1.f / (g.y1 - g.y0);
    const float cx = b.x + b.w / 2.f, cy = b.y + b.h / 2.f;
    const float lo_x = (float)b.x, lo_y = (float)b.y, hi_x = (float)(b.x + b.w - 1), hi_y = (float)(b.y + b.h - 1);
    for (int by = 0; by < BY; ++by)
        for (int bx = 0; bx < BX; ++bx) {
            float d = 0;
            bool inside = true;
            for (int i = 0; i < BS && inside; ++i) {
                const float dy = (((by * BS + i + 0.5f) / CH - g.y0) * sy - 0.5f) * b.h;
                for (int j = 0; j < BS; ++j) {
                    const float dx = (((bx * BS + j + 0.5f) / CW - g.x0) * sx - 0.5f) * b.w;
                    float rx = dx * c - dy * s, ry = dx * s + dy * c;
                    if (g.hflip) rx = -rx;
                    if (g.vflip) ry = -ry;
                    const float X = cx + rx - 0.5f, Y = cy + ry - 0.5f;
                    if (X < lo_x || Y < lo_y || X > hi_x || Y > hi_y) {
                        inside = false;
                        break;
                    }
                    d += K[i][j] * bilinear(f.mean, f.w, f.h, X, Y);
                }
            }
            if (!inside) continue;
            const int bit = owner[by * BX + bx];
            soft[bit] += std::clamp(d, -CLIP, CLIP);
            ++n[bit];
        }
    double num = 0, den = 0;
    for (int k = 0; k < BITS; ++k) {
        num += std::abs(soft[k]);
        den += std::sqrt((double)std::max(n[k], 1));
    }
    return num / den;
}

// 찾은 배치 근처를 조금씩 움직여 가며 표식이 가장 뚜렷한 지점으로 맞춘다
inline double refine(const Frames& f, const Box& b, Geometry& g, const std::vector<int>& owner, std::vector<double>& soft) {
    double best = score_layout(f, b, g, owner, soft);
    for (float step : {0.004f, 0.002f, 0.001f})
        for (int iter = 0; iter < 12; ++iter) {
            bool improved = false;
            for (int k = 0; k < 5; ++k)
                for (int sign : {-1, 1}) {
                    Geometry t = g;
                    float* v[] = {&t.x0, &t.x1, &t.y0, &t.y1, &t.angle};
                    *v[k] += sign * (k == 4 ? step * 50 : step);  // 회전은 0.2° → 0.1° → 0.05°
                    if (t.x1 - t.x0 < 0.3f || t.y1 - t.y0 < 0.3f) continue;
                    const double sc = score_layout(f, b, t, owner, soft);
                    if (sc > best) {
                        best = sc;
                        g = t;
                        improved = true;
                    }
                }
            if (!improved) break;
        }
    return best;
}

// 가공된 영상에서 읽기: 검은 띠 → 반전 4가지 → 가장자리 잘림(0~12%)·회전(±6°) 후보를 훑고, 가장 뚜렷한 후보를 다듬어 번호를 읽는다.
// flip_order: 먼저 시도할 반전 순서 (0 없음, 1 좌우, 2 상하, 3 둘 다). 지문 비교 결과로 정한다
inline Detection detect_transformed(const Bytes& key, const Frames& f, const std::vector<int>& flip_order) {
    const auto owner = wm::layout(key);
    const Box full{0, 0, f.w, f.h}, inner = content_box(f);
    std::vector<std::pair<Box, bool>> bases;
    if (inner.x || inner.y || inner.w != f.w || inner.h != f.h) bases.push_back({inner, true});
    bases.push_back({full, false});
    std::vector<double> soft;
    Detection r;
    r.frames = f.count;
    for (const auto& [box, bars] : bases)
        for (int flip : flip_order) {
            std::vector<std::pair<double, Geometry>> cands;
            auto add = [&](Geometry g) {
                g.hflip = flip & 1;
                g.vflip = (flip & 2) != 0;
                g.bars = bars;
                cands.push_back({score_layout(f, box, g, owner, soft), g});
            };
            for (int cy = 0; cy <= 12; ++cy)
                for (int cx = 0; cx <= 12; ++cx) {
                    Geometry g;
                    g.x0 = cx / 100.f, g.x1 = 1 - g.x0, g.y0 = cy / 100.f, g.y1 = 1 - g.y0;
                    add(g);
                }
            for (int cut = 1; cut <= 12; ++cut)  // 한쪽만 잘린 경우
                for (int edge = 0; edge < 4; ++edge) {
                    Geometry g;
                    float* side[] = {&g.x0, &g.x1, &g.y0, &g.y1};
                    *side[edge] += (edge % 2 ? -cut : cut) / 100.f;
                    add(g);
                }
            for (int a = 1; a <= 12; ++a)
                for (int sign : {-1, 1}) {
                    Geometry g;
                    g.angle = sign * a * 0.5f;
                    add(g);
                }
            std::partial_sort(cands.begin(), cands.begin() + 2, cands.end(), [](auto& a, auto& b) { return a.first > b.first; });
            for (int k = 0; k < 2; ++k) {
                Geometry g = cands[k].second;
                refine(f, box, g, owner, soft);
                score_layout(f, box, g, owner, soft);
                if (decode_soft(soft, key, 2, r)) {
                    r.transformed = true;
                    r.geometry = g;
                    r.soft = soft;
                    for (double v : soft) r.margin += std::abs(v);
                    r.margin /= BITS;
                    return r;
                }
            }
        }
    return r;
}

inline Detection detect_video(const Paths& p, const Bytes& key, const fs::path& video, int max_frames = 900) {
    const auto owner = wm::layout(key);
    Process dec(quoted(p.ffmpeg) + L" -v error -i " + quoted(video.wstring()) +
                    L" -an -vf scale=640:360:flags=area -pix_fmt gray -f rawvideo -",
                true, p.data / L"ffmpeg.log");
    std::vector<unsigned char> buf((size_t)wm::CW * wm::CH);
    std::vector<float> y(buf.size());
    std::vector<double> soft(BITS, 0.0);
    Detection r;
    while (r.frames < max_frames && dec.read(buf.data(), buf.size()) == buf.size()) {
        for (size_t k = 0; k < buf.size(); ++k) y[k] = buf[k];
        wm::accumulate(y, owner, soft);
        ++r.frames;
    }
    dec.finish();
    if (!r.frames) throw std::runtime_error("영상을 읽을 수 없어요: " + utf8(video.wstring()));
    for (double& s : soft) {
        s /= r.frames;
        r.margin += std::abs(s);
    }
    r.margin /= BITS;
    r.soft = soft;
    decode_soft(soft, key, 3, r);
    return r;
}

// ---------------------------------------------------------------- 기록 (TSV)

struct Asset {
    std::string id, sha256, file, registered_at;
};
struct Issue {
    std::string viewer, asset, recipient, device, ip, issued_at, file, source;  // source: 표식을 넣을 때 고른 원본 파일
};

inline std::vector<std::vector<std::string>> read_tsv(const fs::path& file) {
    std::vector<std::vector<std::string>> rows;
    std::ifstream f(file, std::ios::binary);
    std::string line;
    bool header = true;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (header) {
            header = false;
            continue;
        }
        if (line.empty()) continue;
        std::vector<std::string> cols;
        std::istringstream s(line);
        for (std::string c; std::getline(s, c, '\t');) cols.push_back(c);
        rows.push_back(cols);
    }
    return rows;
}

inline void append_tsv(const fs::path& file, const std::string& header, const std::vector<std::string>& cols) {
    fs::create_directories(file.parent_path());
    const bool fresh = !fs::exists(file);
    std::ofstream f(file, std::ios::binary | std::ios::app);
    if (!f) throw std::runtime_error("기록 파일을 쓸 수 없어요: " + utf8(file.wstring()));
    if (fresh) f << header << "\n";
    for (size_t i = 0; i < cols.size(); ++i) f << (i ? "\t" : "") << clean(cols[i]);
    f << "\n";
}

inline std::vector<Asset> assets(const Paths& p) {
    std::vector<Asset> out;
    for (auto& c : read_tsv(p.data / L"assets.tsv"))
        if (c.size() >= 4) out.push_back({c[0], c[1], c[2], c[3]});
    return out;
}

inline std::vector<Issue> issues(const Paths& p) {
    std::vector<Issue> out;
    for (auto& c : read_tsv(p.data / L"issued.tsv"))
        if (c.size() >= 7) out.push_back({c[0], c[1], c[2], c[3], c[4], c[5], c[6], c.size() >= 8 ? c[7] : ""});
    return out;
}

// ---------------------------------------------------------------- 지문 (어떤 원본인지)
// 화면을 32×18로 줄인 밝기 패턴을 초당 약 4장 뽑아 원본마다 data\fp\고유코드.fpt에 저장한다.
// 밝기·대비를 정규화하고 반전 4가지를 모두 비교하므로 크기·비율 변경, 반전, 재압축, 배속이 돼도 원본을 찾는다.
// 지문은 내용에서 뽑으므로 같은 원본의 사본은 모두 같다: '어떤 원본인지'만 알려주고 '누구의 사본인지'는 표식으로 읽는다.

constexpr int FW = 32, FH = 18, FN = FW * FH;
constexpr double FP_MATCH = 0.8;   // 이 이상이면 같은 원본으로 본다
constexpr double FP_SEARCH = 0.6;  // 이 이상이면 가공을 되돌려 표식을 찾아 본다 (많이 잘린 영상은 유사도가 낮아지므로)

// 지문 묶음: 장면마다 정규화한 32×18 패턴과 그 장면의 시각
struct Prints {
    std::vector<std::vector<float>> v;
    std::vector<float> t;
};

inline Prints fingerprints(const Frames& f, const Box& b) {
    Prints out;
    const float bx = b.x / 4.f, by = b.y / 4.f, bw = b.w / 4.f, bh = b.h / 4.f;
    for (size_t k = 0; k < f.thumbs.size(); ++k) {
        const auto& t = f.thumbs[k];
        std::vector<float> v(FN);
        for (int i = 0; i < FH; ++i)
            for (int j = 0; j < FW; ++j) {
                float s = 0;
                for (int a = 0; a < 4; ++a)
                    for (int c = 0; c < 4; ++c)
                        s += bilinear(t, f.tw, f.th, bx + (j + (c + 0.5f) / 4) * bw / FW - 0.5f, by + (i + (a + 0.5f) / 4) * bh / FH - 0.5f);
                v[(size_t)i * FW + j] = s / 16;
            }
        const float mean = std::accumulate(v.begin(), v.end(), 0.f) / FN;
        float norm = 0;
        for (float& x : v) norm += (x -= mean) * x;
        norm = std::sqrt(norm);
        if (norm < 20) continue;  // 거의 단색인 프레임(암전 등)은 비교에 쓰지 않는다
        for (float& x : v) x /= norm;
        out.v.push_back(std::move(v));
        out.t.push_back(f.times[k]);
    }
    return out;
}

// 반전을 적용한 패턴 (flip: 1 좌우, 2 상하, 3 둘 다)
inline void flip_print(const std::vector<float>& s, int flip, std::vector<float>& out) {
    out.resize(FN);
    for (int i = 0; i < FH; ++i)
        for (int j = 0; j < FW; ++j) out[(size_t)i * FW + j] = s[(size_t)(flip & 2 ? FH - 1 - i : i) * FW + (flip & 1 ? FW - 1 - j : j)];
}

// 원본 지문: datap\고유코드.fpt (장면마다 [시각, 패턴 576개] float)
inline Prints asset_fingerprint(const Paths& p, const Asset& a) {
    const fs::path file = p.data / L"fp" / (wide(a.id) + L".fpt");
    Prints out;
    if (fs::exists(file)) {
        std::ifstream f(file, std::ios::binary);
        std::vector<float> row(FN + 1);
        while (f.read((char*)row.data(), (FN + 1) * sizeof(float))) {
            out.t.push_back(row[0]);
            out.v.emplace_back(row.begin() + 1, row.end());
        }
        return out;
    }
    const fs::path src = wide(a.file);
    if (!fs::exists(src)) return out;
    const Frames f = read_frames(p, src, 0);
    out = fingerprints(f, content_box(f));
    fs::create_directories(file.parent_path());
    std::ofstream o(file, std::ios::binary);
    for (size_t k = 0; k < out.v.size(); ++k) {
        o.write((const char*)&out.t[k], sizeof(float));
        o.write((const char*)out.v[k].data(), FN * sizeof(float));
    }
    return out;
}

// 의심 장면 하나와 가장 닮은 원본 장면 (번호, 유사도)
inline std::pair<int, double> best_scene(const std::vector<float>& v, const Prints& orig) {
    std::pair<int, double> best{-1, -1};
    for (size_t j = 0; j < orig.v.size(); ++j) {
        const double m = std::inner_product(v.begin(), v.end(), orig.v[j].begin(), 0.f);
        if (m > best.second) best = {(int)j, m};
    }
    return best;
}

// 장면마다 원본의 몇 초와 맞는지로 재생 속도를 잰다 (1 = 원래 속도, 1.5 = 1.5배속). 알 수 없으면 0
inline double estimate_speed(const Prints& suspect, const Prints& orig, int flip) {
    std::vector<std::pair<float, float>> pts;
    std::vector<float> v;
    for (size_t i = 0; i < suspect.v.size(); ++i) {
        flip_print(suspect.v[i], flip, v);
        const auto [j, sim] = best_scene(v, orig);
        if (j >= 0 && sim > 0.9) pts.push_back({suspect.t[i], orig.t[j]});
    }
    std::vector<double> slopes;
    for (size_t a = 0; a < pts.size(); ++a)
        for (size_t b = a + 1; b < pts.size(); ++b) {
            const double dt = pts[b].first - pts[a].first;
            if (dt >= 1.0) slopes.push_back((pts[b].second - pts[a].second) / dt);
        }
    if (slopes.size() < 5) return 0;
    std::nth_element(slopes.begin(), slopes.begin() + slopes.size() / 2, slopes.end());
    return slopes[slopes.size() / 2];
}

struct Match {
    std::string asset;      // 가장 비슷한 원본의 고유 코드
    double similarity = 0;  // 0~1. FP_MATCH 이상이어야 같은 원본
    int flip = 0;          // 가장 잘 맞은 반전 (0 없음, 1 좌우, 2 상하, 3 둘 다)
    std::vector<int> flip_order{0, 1, 2, 3};
};

// 의심 영상의 각 장면마다 원본에서 가장 닮은 장면을 찾아 평균 유사도를 낸다 (장면 순서·속도와 무관)
inline Match match_fingerprint(const Paths& p, const Prints& suspect) {
    Match best;
    if (suspect.v.empty()) return best;
    for (const auto& a : assets(p)) {
        const Prints orig = asset_fingerprint(p, a);
        if (orig.v.empty()) continue;
        double score[4] = {};
        std::vector<float> v;
        for (int flip = 0; flip < 4; ++flip) {
            for (const auto& s : suspect.v) {
                flip_print(s, flip, v);
                score[flip] += best_scene(v, orig).second;
            }
            score[flip] /= suspect.v.size();
        }
        std::vector<int> order{0, 1, 2, 3};
        std::sort(order.begin(), order.end(), [&](int x, int y) { return score[x] > score[y]; });
        if (score[order[0]] > best.similarity) best = {a.id, score[order[0]], order[0], order};
    }
    return best;
}

// 원본 영상 등록: 같은 파일(SHA-256)이면 기존 고유 코드를 돌려준다. 등록할 때 지문도 저장한다
inline Asset register_asset(const Paths& p, const fs::path& video) {
    std::string sha;
    for (unsigned char b : hash({}, read_file(video))) sha += hex(b, 2);
    const auto existing = assets(p);
    for (const auto& a : existing)
        if (a.sha256 == sha) {
            asset_fingerprint(p, a);
            return a;
        }
    std::string id;
    do {
        const Bytes r = random_bytes(2);
        id = hex(((uint32_t)r[0] << 8) | r[1], 4);
    } while (std::any_of(existing.begin(), existing.end(), [&](const Asset& a) { return a.id == id; }));
    const Asset a{id, sha, utf8(fs::absolute(video).wstring()), now_text()};
    append_tsv(p.data / L"assets.tsv", "asset_id\tsha256\tsource_file\tregistered_at", {a.id, a.sha256, a.file, a.registered_at});
    asset_fingerprint(p, a);
    return a;
}

// 사본 만들기: 새 개별 식별 번호를 만들고, 표식을 넣은 MP4를 저장한 뒤 기록한다
// selected: 사용자가 고른 파일. 내용이 같은 파일이 이미 등록돼 있어도 결과는 고른 파일을 원본으로 쓴다
// out_dir: 저장할 폴더. 비우면 원본과 같은 폴더 (쓸 수 없으면 issued\)
inline Issue issue_copy(const Paths& p, const std::string& asset_id, const std::string& recipient, const std::string& device,
                        const std::string& ip, const Progress& progress = {}, const fs::path& selected = {}, const fs::path& out_dir = {}) {
    const auto list = assets(p);
    const auto it = std::find_if(list.begin(), list.end(), [&](const Asset& a) { return a.id == asset_id; });
    if (it == list.end()) throw std::runtime_error("등록되지 않은 고유 코드예요: " + asset_id);
    const auto issued = issues(p);
    std::string viewer;
    do {
        const Bytes r = random_bytes(3);
        viewer = hex(((uint32_t)r[0] << 16) | ((uint32_t)r[1] << 8) | r[2], 6);
    } while (std::any_of(issued.begin(), issued.end(), [&](const Issue& i) { return i.viewer == viewer; }));

    // 원본과 같은 폴더에 '원본이름_표식_식별번호.mp4'로 저장. 그 폴더에 쓸 수 없으면 issued\에 저장
    const fs::path source = selected.empty() ? fs::path(wide(it->file)) : fs::absolute(selected);
    fs::path dir = out_dir.empty() ? source.parent_path() : out_dir;
    if (out_dir.empty()) {
        const fs::path probe_file = dir / L".forensic_write_test";
        std::ofstream test(probe_file);
        const bool writable = (bool)test;
        test.close();
        std::error_code ec;
        fs::remove(probe_file, ec);
        if (!writable) dir = p.issued;
    }
    fs::create_directories(dir);
    const fs::path out = dir / (source.stem().wstring() + L"_표식_" + wide(viewer) + L".mp4");
    const Bytes key = secret_key(p);
    mark_video(p, source, out, make_message(key, std::stoul(asset_id, nullptr, 16), std::stoul(viewer, nullptr, 16)),
               wm::layout(key), progress);
    const Issue i{viewer, asset_id, recipient, device, ip, now_text(), utf8(out.wstring()), utf8(source.wstring())};
    append_tsv(p.data / L"issued.tsv", "viewer_id\tasset_id\tmemo\tdevice\tip\tissued_at\tfile\tsource_file",
               {i.viewer, i.asset, i.recipient, i.device, i.ip, i.issued_at, i.file, i.source});
    return i;
}

// 검사 결과를 기록과 대조해서 사람이 읽을 수 있는 판정으로
struct Verdict {
    std::string result;  // traced | not_issued | original_only(원본은 찾았지만 번호는 못 읽음) | unidentified
    Detection detection;
    Match match;  // 지문 비교 결과 (기본 검출로 바로 읽힌 경우에는 하지 않음)
    Issue issue;
    Asset asset;
};

// 1) 그대로 읽어 본다 → 2) 안 되면 지문으로 어떤 원본인지 찾고, 그 원본의 영상이면 가공(반전·띠·잘림·회전)을 되돌려 다시 읽는다
inline Verdict trace(const Paths& p, const fs::path& video) {
    Verdict v;
    const Bytes key = secret_key(p);
    v.detection = detect_video(p, key, video);
    if (!v.detection.verified) {
        const Frames f = read_frames(p, video, 900);
        v.match = match_fingerprint(p, fingerprints(f, content_box(f)));
        if (v.match.similarity >= FP_SEARCH) {
            const Detection d = detect_transformed(key, f, v.match.flip_order);
            if (d.verified) v.detection = d;
        }
    }
    if (!v.detection.verified) {
        if (v.match.similarity < FP_MATCH) v.match.asset.clear();
        v.result = v.match.asset.empty() ? "unidentified" : "original_only";
        for (const auto& x : assets(p))
            if (x.id == v.match.asset) v.asset = x;
        return v;
    }
    const std::string a = hex(v.detection.asset, 4), w = hex(v.detection.viewer, 6);
    for (const auto& x : assets(p))
        if (x.id == a) v.asset = x;
    for (const auto& x : issues(p))
        if (x.viewer == w && x.asset == a) v.issue = x;
    v.result = v.issue.viewer.empty() ? "not_issued" : "traced";
    if (v.issue.viewer.empty()) {
        v.issue.viewer = w;
        v.issue.asset = a;
    }
    return v;
}

inline std::string verdict_json(const Verdict& v, const fs::path& video) {
    auto esc = [](const std::string& s) {
        std::string r;
        for (char c : s) {
            if (c == '"' || c == '\\') r += '\\';
            r += c;
        }
        return r;
    };
    std::ostringstream j;
    j << std::setprecision(4) << "{\n  \"result\": \"" << v.result << "\",\n  \"video\": \"" << esc(utf8(video.wstring())) << "\",\n";
    if (!v.match.asset.empty()) j << "  \"fingerprint_asset\": \"" << v.match.asset << "\",\n";
    if (v.match.similarity > 0) j << "  \"fingerprint_similarity\": " << v.match.similarity << ",\n";
    if (v.detection.transformed) j << "  \"undone_edits\": \"" << esc(describe(v.detection.geometry)) << "\",\n";
    if (v.result == "traced" || v.result == "not_issued")
        j << "  \"asset_id\": \"" << v.issue.asset << "\",\n  \"viewer_id\": \"" << v.issue.viewer << "\",\n  \"recipient\": \""
          << esc(v.issue.recipient) << "\",\n  \"device\": \"" << esc(v.issue.device) << "\",\n  \"ip\": \"" << esc(v.issue.ip)
          << "\",\n  \"issued_at\": \"" << v.issue.issued_at << "\",\n  \"source_file\": \"" << esc(v.asset.file) << "\",\n";
    j << "  \"frames_checked\": " << v.detection.frames << ",\n  \"corrected_bits\": " << v.detection.corrected_bits
      << ",\n  \"signal_margin\": " << v.detection.margin << "\n}\n";
    return j.str();
}

}  // namespace fm
