#pragma once
// FRAME 업로드 판정기: 영상이 올라오면 코드(표식)와 지문으로 어떤 원본인지 확인한다.
//  - 처음 보는 영상: 새 원본으로 등록하고, 보이지 않는 코드를 넣은 영상을 사이트에 돌려준다
//  - 다른 사람의 원본: 원작자가 2차 창작을 허용했으면 통과, 아니면 업로드를 막고 경고 1회
//    우회 가공(반전·회전·잘림·검은 띠·배속·크기/비율 변경·코드 훼손)이 보이거나 경고가 2회가 되면 계정 정지
// 판정의 각 단계·이미지·비트를 Job에 남겨 업로드 페이지가 실시간으로 보여준다.
#include "server.h"

namespace fm {
namespace site {

// ---------------------------------------------------------------- 사이트 기록 (data\frame\)

struct Original {
    std::string asset, owner, allow, title, at;  // allow: O(2차 창작 허용) / X
};
struct Account {
    std::string name;
    int warnings = 0;
    bool suspended = false;
    std::string reason, at;
};

inline fs::path dir(const Paths& p) { return p.data / L"frame"; }

inline std::vector<Original> originals(const Paths& p) {
    std::vector<Original> out;
    for (auto& c : read_tsv(dir(p) / L"originals.tsv"))
        if (c.size() >= 5) out.push_back({c[0], c[1], c[2], c[3], c[4]});
    return out;
}

inline std::vector<Account> accounts(const Paths& p) {
    std::vector<Account> out;
    for (auto& c : read_tsv(dir(p) / L"accounts.tsv"))
        if (c.size() >= 5) out.push_back({c[0], std::atoi(c[1].c_str()), c[2] == "1", c[3], c[4]});
    return out;
}

inline Account account(const Paths& p, const std::string& name) {
    for (const auto& a : accounts(p))
        if (a.name == name) return a;
    return {name};
}

inline void save_account(const Paths& p, Account a) {
    a.at = now_text();
    auto all = accounts(p);
    const auto it = std::find_if(all.begin(), all.end(), [&](const Account& x) { return x.name == a.name; });
    if (it != all.end()) *it = a;
    else all.push_back(a);
    fs::create_directories(dir(p));
    std::ofstream f(dir(p) / L"accounts.tsv", std::ios::binary | std::ios::trunc);
    f << "account\twarnings\tsuspended\treason\tupdated_at\n";
    for (const auto& x : all) f << clean(x.name) << "\t" << x.warnings << "\t" << (x.suspended ? 1 : 0) << "\t" << clean(x.reason) << "\t" << x.at << "\n";
}

inline std::string account_json(const Account& a) {
    return "{\"name\":" + http::json(a.name) + ",\"warnings\":" + std::to_string(a.warnings) + ",\"suspended\":" + (a.suspended ? "true" : "false") +
           ",\"reason\":" + http::json(a.reason) + "}";
}

// ---------------------------------------------------------------- 판정 과정을 보여주기 위한 이미지

struct Image {
    std::string caption;
    int w = 0, h = 0;
    std::vector<unsigned char> rgb;
};

// 영상의 t초 장면 한 장 (RGB)
inline Image grab(const Paths& p, const fs::path& video, double t, int w, int h, const std::string& caption) {
    Image img{caption, w, h, std::vector<unsigned char>((size_t)w * h * 3, 0)};
    wchar_t ss[32];
    swprintf_s(ss, L"%.3f", std::max(0.0, t));
    Process dec(quoted(p.ffmpeg) + L" -v error -ss " + ss + L" -i " + quoted(video.wstring()) + L" -frames:v 1 -an -vf scale=" + std::to_wstring(w) + L":" +
                    std::to_wstring(h) + L":flags=area -pix_fmt rgb24 -f rawvideo -",
                true, p.data / L"ffmpeg.log");
    dec.read(img.rgb.data(), img.rgb.size());
    dec.finish();
    return img;
}

// 가공을 되돌린 화면: 올린 영상 장면(src)의 내용 영역 b(src 좌표)에서 원본 화면 배치 g대로 다시 뽑는다 (detect의 score_layout과 같은 계산)
inline Image unwarp(const Image& src, const Box& b, const Geometry& g, int w, int h, const std::string& caption) {
    Image out{caption, w, h, std::vector<unsigned char>((size_t)w * h * 3, 24)};
    const float rad = g.angle * 3.14159265f / 180.f, c = std::cos(rad), s = std::sin(rad);
    const float sx = 1.f / (g.x1 - g.x0), sy = 1.f / (g.y1 - g.y0), cx = b.x + b.w / 2.f, cy = b.y + b.h / 2.f;
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x) {
            const float dx = (((x + 0.5f) / w - g.x0) * sx - 0.5f) * b.w, dy = (((y + 0.5f) / h - g.y0) * sy - 0.5f) * b.h;
            float rx = dx * c - dy * s, ry = dx * s + dy * c;
            if (g.hflip) rx = -rx;
            if (g.vflip) ry = -ry;
            const float X = cx + rx - 0.5f, Y = cy + ry - 0.5f;
            if (X < b.x || Y < b.y || X > b.x + b.w - 1 || Y > b.y + b.h - 1) continue;  // 잘려 나간 부분은 어둡게 남긴다
            const int x0 = std::min((int)X, src.w - 2), y0 = std::min((int)Y, src.h - 2);
            const float ax = X - x0, ay = Y - y0;
            for (int k = 0; k < 3; ++k) {
                auto at = [&](int xx, int yy) { return (float)src.rgb[((size_t)yy * src.w + xx) * 3 + k]; };
                const float v = (at(x0, y0) * (1 - ax) + at(x0 + 1, y0) * ax) * (1 - ay) + (at(x0, y0 + 1) * (1 - ax) + at(x0 + 1, y0 + 1) * ax) * ay;
                out.rgb[((size_t)y * w + x) * 3 + k] = (unsigned char)std::clamp((int)std::lround(v), 0, 255);
            }
        }
    return out;
}

// 두 장면의 밝기 차이를 gain배로 키워 색으로 (밝아진 곳은 주황, 어두워진 곳은 파랑): 보이지 않는 코드를 눈으로 보기 위함
inline Image amplified_diff(const Image& a, const Image& b, float gain, const std::string& caption) {
    Image out{caption, a.w, a.h, std::vector<unsigned char>(a.rgb.size())};
    for (size_t i = 0; i < (size_t)a.w * a.h; ++i) {
        auto lum = [&](const Image& m) { return 0.299f * m.rgb[i * 3] + 0.587f * m.rgb[i * 3 + 1] + 0.114f * m.rgb[i * 3 + 2]; };
        const float d = std::clamp((lum(b) - lum(a)) * gain / 255.f, -1.f, 1.f);
        const float hot[3] = {255, 120, 80}, cold[3] = {80, 170, 255}, base[3] = {18, 18, 22};
        for (int k = 0; k < 3; ++k) out.rgb[i * 3 + k] = (unsigned char)(base[k] + (d > 0 ? hot[k] - base[k] : cold[k] - base[k]) * std::abs(d));
    }
    return out;
}

inline int even_height(int w, const VideoInfo& info) { return std::max(2, (int)std::lround((double)w * info.h / info.w / 2) * 2); }

inline std::string ratio_name(int w, int h) {
    const double r = (double)w / h;
    const std::pair<double, const char*> known[] = {{16.0 / 9, "16:9"}, {4.0 / 3, "4:3"}, {9.0 / 16, "9:16"}, {1.0, "1:1"}, {21.0 / 9, "21:9"}, {3.0 / 4, "3:4"}};
    for (const auto& [v, name] : known)
        if (std::abs(r / v - 1) < 0.02) return name;
    char b[16];
    sprintf_s(b, "%.2f:1", r);
    return b;
}

// ---------------------------------------------------------------- 판정 작업 (진행 상황을 페이지가 0.3초마다 읽어 간다)

struct Step {
    std::string key, title, status = "wait", detail;  // status: wait | run | ok | warn | fail | skip
};

struct Job {
    std::mutex m;
    std::vector<Step> steps;
    std::vector<Image> images;
    std::string bits, fingerprint, edits, result;  // 각각 JSON (없으면 빈 값)
    std::atomic<int> progress{0}, total{0};  // 코드 삽입 진행 (프레임)
    fs::path output;  // 코드를 넣은 영상 (새 원본일 때)

    void add(const std::string& key, const std::string& title) {
        std::lock_guard<std::mutex> l(m);
        steps.push_back({key, title});
    }
    void set(const std::string& key, const std::string& status, const std::string& detail = "") {
        std::lock_guard<std::mutex> l(m);
        for (auto& s : steps)
            if (s.key == key) s.status = status, s.detail = detail;
    }
    void fail_running(const std::string& detail) {
        std::lock_guard<std::mutex> l(m);
        for (auto& s : steps)
            if (s.status == "run") s.status = "fail", s.detail = detail;
    }
    // 64비트를 고유 코드 16 / 개별 번호 24 / 위조 방지값 24로 나눠 보여준다. soft: 비트별 신호 (부호=값, 크기=확신)
    void set_bits(const std::vector<double>& soft, uint64_t message, bool verified, const std::string& caption) {
        double peak = 1e-9;
        for (double s : soft) peak = std::max(peak, std::abs(s));
        std::string v = "[";
        for (size_t i = 0; i < soft.size(); ++i) {
            char b[16];
            sprintf_s(b, "%s%.2f", i ? "," : "", soft[i] / peak);
            v += b;
        }
        std::lock_guard<std::mutex> l(m);
        bits = "{\"soft\":" + v + "],\"asset\":\"" + hex(message >> 48, 4) + "\",\"id\":\"" + hex((message >> 24) & 0xFFFFFF, 6) + "\",\"tag\":\"" +
               hex(message & 0xFFFFFF, 6) + "\",\"verified\":" + (verified ? "true" : "false") + ",\"caption\":" + http::json(caption) + "}";
    }
    void put_image(Image img) {
        std::lock_guard<std::mutex> l(m);
        images.push_back(std::move(img));
    }
    void finish(const std::string& json) {
        std::lock_guard<std::mutex> l(m);
        result = json;
    }
    std::string to_json() {
        std::lock_guard<std::mutex> l(m);
        std::string j = "{\"done\":" + std::string(result.empty() ? "false" : "true") + ",\"progress\":" + std::to_string(progress.load()) +
                        ",\"total\":" + std::to_string(total.load()) + ",\"steps\":[";
        for (size_t i = 0; i < steps.size(); ++i)
            j += (i ? "," : "") + std::string("{\"key\":") + http::json(steps[i].key) + ",\"title\":" + http::json(steps[i].title) +
                 ",\"status\":" + http::json(steps[i].status) + ",\"detail\":" + http::json(steps[i].detail) + "}";
        j += "],\"images\":[";
        for (size_t i = 0; i < images.size(); ++i)
            j += (i ? "," : "") + std::string("{\"caption\":") + http::json(images[i].caption) + ",\"w\":" + std::to_string(images[i].w) +
                 ",\"h\":" + std::to_string(images[i].h) + "}";
        j += "],\"bits\":" + (bits.empty() ? "null" : bits) + ",\"fingerprint\":" + (fingerprint.empty() ? "null" : fingerprint) +
             ",\"edits\":" + (edits.empty() ? "null" : edits) + ",\"result\":" + (result.empty() ? "null" : result) + "}";
        return j;
    }
};

inline std::string result_json(const std::string& decision, const std::string& headline, const std::string& message, const Account& acc,
                               const std::string& asset = "", const std::string& code = "", const std::string& owner = "") {
    return "{\"decision\":" + http::json(decision) + ",\"headline\":" + http::json(headline) + ",\"message\":" + http::json(message) +
           ",\"asset\":" + http::json(asset) + ",\"code\":" + http::json(code) + ",\"owner\":" + http::json(owner) + ",\"account\":" + account_json(acc) + "}";
}

inline std::string list_json(const std::vector<std::string>& items) {
    std::string j = "[";
    for (size_t i = 0; i < items.size(); ++i) j += (i ? "," : "") + http::json(items[i]);
    return j + "]";
}

inline std::string join(const std::vector<std::string>& items, const char* sep = ", ") {
    std::string s;
    for (const auto& x : items) s += (s.empty() ? "" : sep) + x;
    return s;
}

// 업로드 한 건 판정. 판정과 등록은 한 번에 하나씩 (기록 파일을 동시에 쓰지 않도록)
inline void judge(const Paths& p, Job& job, const fs::path& upload, const std::string& name, bool allow, const std::string& title, const std::string& ip) {
    static std::mutex one;
    std::lock_guard<std::mutex> lock(one);
    job.add("account", "계정 확인");
    job.add("code", "코드 읽기");
    job.add("fingerprint", "지문 비교");
    job.add("restore", "가공 되돌리기");
    job.add("owner", "원작자 · 2차 창작 확인");

    Account acc = account(p, name);
    if (acc.suspended) {
        job.set("account", "fail", "정지된 계정 · " + acc.reason);
        for (const char* k : {"code", "fingerprint", "restore", "owner"}) job.set(k, "skip");
        job.finish(result_json("suspended", "정지된 계정 · 업로드 불가", "이 계정은 정지되어 영상을 올릴 수 없습니다. 사유: " + acc.reason, acc));
        return;
    }
    job.set("account", "ok", name + " · 경고 " + std::to_string(acc.warnings) + "회");

    // 1) 코드 읽기: 영상 그대로 읽는다
    const Bytes key = secret_key(p);
    job.set("code", "run", "모든 프레임의 8×8 블록에서 64비트를 모으는 중");
    Detection d = detect_video(p, key, upload);
    auto message_of = [&](const Detection& x) { return x.verified ? make_message(key, x.asset, x.viewer) : 0ull; };
    {
        uint64_t hard = 0;
        for (double s : d.soft) hard = (hard << 1) | (s > 0 ? 1u : 0u);
        job.set_bits(d.soft, d.verified ? message_of(d) : hard, d.verified,
                     d.verified ? "영상에서 그대로 읽은 코드 (위조 방지값 일치)" : "그대로 읽은 신호 · 위조 방지값 불일치 = 코드 없음 또는 가공됨");
    }
    job.set("code", d.verified ? "ok" : "warn", d.verified ? "고유 코드 " + hex(d.asset, 4) + " · 번호 " + hex(d.viewer, 6) : "그대로는 읽히지 않음");

    // 2) 지문 비교: 어떤 원본인지
    job.set("fingerprint", "run", "장면마다 32×18 밝기 패턴을 원본들과 비교하는 중");
    const Frames f = read_frames(p, upload, 900);
    const Box box = content_box(f);
    const Prints sp = fingerprints(f, box);
    const Match m = match_fingerprint(p, sp);
    {
        std::lock_guard<std::mutex> l(job.m);
        char b[160];
        sprintf_s(b, "{\"similarity\":%.3f,\"match\":%.2f,\"search\":%.2f,\"asset\":", m.similarity, FP_MATCH, FP_SEARCH);
        job.fingerprint = b + http::json(m.asset) + ",\"flip\":" + std::to_string(m.flip) + "}";
    }
    const int pct = (int)std::lround(m.similarity * 100);
    if (m.similarity >= FP_MATCH) job.set("fingerprint", "ok", "원본 " + m.asset + "와 " + std::to_string(pct) + "% 일치");
    else if (m.similarity >= FP_SEARCH) job.set("fingerprint", "warn", "원본 " + m.asset + "와 " + std::to_string(pct) + "% 비슷 · 많이 가공된 듯");
    else job.set("fingerprint", "skip", "등록된 원본 중 비슷한 영상 없음 (최고 " + std::to_string(pct) + "%)");

    // 3) 가공 되돌리기: 그대로 안 읽혔고 등록된 원본과 비슷하면, 반전·띠·잘림·회전을 되돌려 다시 읽는다
    if (d.verified) {
        job.set("restore", "skip", "그대로 읽혀서 필요 없음");
    } else if (m.similarity >= FP_SEARCH) {
        job.set("restore", "run", "검은 띠 · 반전 4가지 · 잘림 · 회전 후보를 훑는 중");
        const Detection t = detect_transformed(key, f, m.flip_order);
        if (t.verified) {
            d = t;
            job.set_bits(d.soft, message_of(d), true, "가공을 되돌려 읽은 코드 (위조 방지값 일치)");
            job.set("restore", "ok", describe(d.geometry) + " → 되돌림");
        } else {
            job.set("restore", "fail", "되돌려도 코드를 읽지 못함 (코드 훼손)");
        }
    } else {
        job.set("restore", "skip", "등록된 원본이 아니라 건너뜀");
    }

    // 어떤 원본인지: 코드가 우선, 없으면 지문
    const std::string asset_id = d.verified ? hex(d.asset, 4) : m.similarity >= FP_MATCH ? m.asset : "";
    Asset asset;
    for (const auto& a : assets(p))
        if (a.id == asset_id) asset = a;

    // 보여줄 장면: 올린 영상의 가운데 장면과, 지문으로 찾은 원본의 같은 장면
    const VideoInfo up = probe(p, upload, false);
    const int flip = d.transformed ? (d.geometry.hflip ? 1 : 0) | (d.geometry.vflip ? 2 : 0) : m.flip;
    const double t_mid = sp.t.empty() ? 0.0 : sp.t[sp.t.size() / 2];
    double t_orig = t_mid;
    Prints op;
    if (!asset.id.empty()) {
        op = asset_fingerprint(p, asset);
        if (!sp.v.empty() && !op.v.empty()) {
            std::vector<float> v;
            flip_print(sp.v[sp.v.size() / 2], flip, v);
            const auto [j, sim] = best_scene(v, op);
            if (j >= 0) t_orig = op.t[(size_t)j];
        }
    }
    const int W = 320, H = 180;
    Image shot = grab(p, upload, t_mid, W, even_height(W, up), "올린 영상");
    job.put_image(shot);
    if (d.transformed) {
        const float kx = (float)shot.w / f.w, ky = (float)shot.h / f.h;
        const Box b{(int)std::lround(box.x * kx), (int)std::lround(box.y * ky), (int)std::lround(box.w * kx), (int)std::lround(box.h * ky)};
        job.put_image(unwarp(shot, b, d.geometry, W, H, "가공을 되돌린 화면"));
    }
    if (!asset.id.empty() && fs::exists(wide(asset.file))) job.put_image(grab(p, wide(asset.file), t_orig, W, H, "등록된 원본 " + asset.id));

    // 4) 원작자 · 2차 창작
    const auto origs = originals(p);
    const auto orig = std::find_if(origs.begin(), origs.end(), [&](const Original& o) { return o.asset == asset_id; });
    if (asset_id.empty() || orig == origs.end()) {
        // 처음 보는 영상(또는 주인 없는 등록 영상) → 이 계정의 원본으로 등록하고 코드를 넣는다
        job.set("owner", "ok", asset_id.empty() ? "처음 보는 영상 → 새 원본" : "주인 없는 등록 영상 " + asset_id + " → 이 계정의 원본");
        job.add("embed", "코드 만들기 · 삽입");
        job.add("verify", "삽입 확인");
        if (asset.id.empty()) asset = register_asset(p, upload);
        const fs::path source = fs::exists(wide(asset.file)) ? fs::path(wide(asset.file)) : upload;
        job.set("embed", "run", "고유 코드 " + asset.id + " + 새 번호 + 위조 방지값 → 64비트를 모든 프레임에");
        job.total = estimate_frames(p, source);
        const Issue issue = issue_copy(p, asset.id, "FRAME 업로드: " + title, "FRAME · " + name, ip, [&](int n) { job.progress = n; }, source,
                                       dir(p) / L"marked");
        const uint64_t msg = make_message(key, std::stoul(asset.id, nullptr, 16), std::stoul(issue.viewer, nullptr, 16));
        std::vector<double> ideal(BITS);
        for (int i = 0; i < BITS; ++i) ideal[i] = (msg >> (BITS - 1 - i)) & 1 ? 1.0 : -1.0;
        job.set_bits(ideal, msg, true, "새로 넣은 64비트 코드");
        job.set("embed", "ok", "고유 코드 " + asset.id + " · 번호 " + issue.viewer);
        job.set("verify", "run", "저장한 영상에서 코드를 다시 읽는 중");
        const Detection v = detect_video(p, key, wide(issue.file));
        const bool same = v.verified && hex(v.viewer, 6) == issue.viewer;
        job.set_bits(v.soft, msg, same, "저장한 영상에서 다시 읽은 코드");
        char sig[64];
        sprintf_s(sig, " · 신호 %.0f", v.margin);
        job.set("verify", same ? "ok" : "fail", same ? std::string("넣은 번호와 일치") + sig : "다시 읽지 못함");
        {
            // 원본 · 코드를 넣은 영상 · 차이를 키운 그림 (사람 눈에는 같아 보이지만 코드가 들어 있다)
            Image a = grab(p, source, t_mid, W, H, "원본"), b = grab(p, wide(issue.file), t_mid, W, H, "코드를 넣은 영상");
            Image diff = amplified_diff(a, b, 12, "차이 ×12 = 보이지 않는 코드");
            std::lock_guard<std::mutex> l(job.m);
            job.images = {a, b, diff};
            job.output = wide(issue.file);
        }
        append_tsv(dir(p) / L"originals.tsv", "asset_id\towner\tallow_derivative\ttitle\tregistered_at", {asset.id, name, allow ? "O" : "X", title, now_text()});
        job.finish(result_json("registered", "새 원본 등록 · 코드 삽입 완료",
                               "보이지 않는 코드(고유 코드 " + asset.id + " · 번호 " + issue.viewer + ")를 넣은 영상으로 등록합니다. 2차 창작: " +
                                   (allow ? "허용" : "불허"),
                               acc, asset.id, issue.viewer, name));
        return;
    }
    const std::string how = d.verified ? "코드" : "지문";
    if (orig->owner == name) {
        job.set("owner", "ok", "내가 올린 원본 " + asset_id + " (" + how + "로 확인)");
        job.finish(result_json("allowed_own", "내 원본 · 업로드 허용", "내가 올린 원본(" + asset_id + ")이라 그대로 등록합니다.", acc, asset_id, "", name));
        return;
    }
    if (orig->allow == "O") {
        job.set("owner", "ok", "원작자 " + orig->owner + " · 2차 창작 허용 (" + how + "로 확인)");
        job.finish(result_json("allowed_derivative", "2차 창작 허용 원본 · 업로드 허용",
                               "원작자 " + orig->owner + "님이 2차 창작을 허용한 영상(" + asset_id + ")이라 등록을 허용합니다.", acc, asset_id, "", orig->owner));
        return;
    }
    job.set("owner", "fail", "원작자 " + orig->owner + " · 2차 창작 불허 (" + how + "로 확인)");

    // 5) 우회 가공 검사: 되돌린 가공 + 원본과 비교한 크기·비율·속도 + 코드 훼손
    job.add("bypass", "우회 가공 검사");
    job.add("decision", "제재");
    job.set("bypass", "run", "원본과 크기 · 비율 · 재생 속도를 비교하는 중");
    std::vector<std::string> edits = d.transformed ? edit_list(d.geometry) : std::vector<std::string>{};
    if (fs::exists(wide(asset.file))) {
        const VideoInfo o = probe(p, wide(asset.file), false);
        if (!d.transformed) {
            if (std::abs(((double)up.w / up.h) / ((double)o.w / o.h) - 1) > 0.03)
                edits.push_back("화면 비율 변경 (" + ratio_name(o.w, o.h) + " → " + ratio_name(up.w, up.h) + ")");
            else if (up.w != o.w || up.h != o.h)
                edits.push_back("크기 변경 (" + std::to_string(o.w) + "×" + std::to_string(o.h) + " → " + std::to_string(up.w) + "×" + std::to_string(up.h) + ")");
        }
        std::string sha;
        for (unsigned char b : hash({}, read_file(upload))) sha += hex(b, 2);
        if (!d.verified && sha != asset.sha256) edits.push_back("코드 훼손");
    }
    const double speed = estimate_speed(sp, op, flip);
    if (speed > 0 && std::abs(speed - 1) > 0.08) {
        char b[48];
        sprintf_s(b, "배속 ×%.2f", speed);
        edits.push_back(b);
    }
    {
        std::lock_guard<std::mutex> l(job.m);
        job.edits = list_json(edits);
    }
    job.set("bypass", edits.empty() ? "ok" : "fail", edits.empty() ? "가공 흔적 없음" : join(edits));

    ++acc.warnings;
    if (!edits.empty()) acc.suspended = true, acc.reason = "우회 시도: " + join(edits);
    else if (acc.warnings >= 2) acc.suspended = true, acc.reason = "경고 2회 누적";
    save_account(p, acc);
    const std::string base = "원작자 " + orig->owner + "님이 2차 창작을 허용하지 않은 영상(" + asset_id + ")입니다.";
    if (acc.suspended) {
        job.set("decision", "fail", "업로드 불허 + 계정 정지");
        job.finish(result_json("blocked", "업로드 불허 · 계정 정지", base + " " + acc.reason + "로 계정을 정지합니다.", acc, asset_id, "", orig->owner));
    } else {
        job.set("decision", "warn", "업로드 불허 + 경고 1회");
        job.finish(result_json("blocked", "업로드 불허 · 경고 " + std::to_string(acc.warnings) + "회",
                               base + " 경고를 한 번 더 받거나 가공해서 올리려 하면 계정이 정지됩니다.", acc, asset_id, "", orig->owner));
    }
}

// ---------------------------------------------------------------- 사이트 서버
// GET  /                       업로드 사이트 (video-upload-client.html)
// GET  /api/account?name=      계정 상태
// POST /api/upload             본문: 영상 파일. 헤더 X-Account, X-Allow(1/0), X-Title, X-Filename (URL 인코딩). 응답: {"job": id}
// GET  /api/job/<id>           판정 진행 상황·결과
// GET  /api/job/<id>/image/<n> 판정 이미지 n번 (RGB 원시 바이트)
// GET  /api/job/<id>/file      코드를 넣은 영상 (새 원본일 때)

class SiteServer {
public:
    std::string start(const Paths& p, int port = 8090) {
        auto st = std::make_shared<State>();
        st->p = p;
        const int used = listener_.start(port, [st](SOCKET c, const std::string& ip) { handle(st, c, ip); });
        address_ = "http://127.0.0.1:" + std::to_string(used) + "/";
        return address_;
    }
    void stop() { listener_.stop(); }
    const std::string& address() const { return address_; }

private:
    struct State {
        Paths p;
        std::mutex m;
        std::map<std::string, std::shared_ptr<Job>> jobs;
        std::shared_ptr<Job> find(const std::string& id) {
            std::lock_guard<std::mutex> l(m);
            const auto it = jobs.find(id);
            return it == jobs.end() ? nullptr : it->second;
        }
    };

    static void upload(const std::shared_ptr<State>& st, SOCKET c, const http::Request& req, const std::string& ip) {
        const std::string name = http::url_decode(req.header("x-account")), title = http::url_decode(req.header("x-title")),
                          file_name = http::url_decode(req.header("x-filename"));
        const uint64_t length = std::strtoull(req.header("content-length").c_str(), nullptr, 10);
        if (name.empty()) return http::reply(c, "400 Bad Request", "application/json", "{\"error\":\"계정 이름이 필요해요\"}");
        if (!length || length > 600ull * 1024 * 1024) return http::reply(c, "413 Payload Too Large", "application/json", "{\"error\":\"영상 크기를 확인하세요\"}");
        const Bytes r = random_bytes(4);
        const std::string id = hex(((uint32_t)r[0] << 24) | ((uint32_t)r[1] << 16) | ((uint32_t)r[2] << 8) | r[3], 8);
        std::string ext = fs::path(wide(file_name)).extension().string();
        if (ext.size() < 2 || ext.size() > 5 || !std::all_of(ext.begin() + 1, ext.end(), [](char ch) { return isalnum((unsigned char)ch); })) ext = ".mp4";
        const fs::path saved = dir(st->p) / L"uploads" / (wide(id) + wide(ext));
        fs::create_directories(saved.parent_path());
        {
            std::ofstream out(saved, std::ios::binary);
            uint64_t got = std::min<uint64_t>(req.body_start.size(), length);
            out.write(req.body_start.data(), (std::streamsize)got);
            std::vector<char> buf(1 << 20);
            while (got < length) {
                const int n = recv(c, buf.data(), (int)std::min<uint64_t>(buf.size(), length - got), 0);
                if (n <= 0) break;
                out.write(buf.data(), n);
                got += (uint64_t)n;
            }
            if (got < length) return http::reply(c, "400 Bad Request", "application/json", "{\"error\":\"영상을 끝까지 받지 못했어요\"}");
        }
        auto job = std::make_shared<Job>();
        {
            std::lock_guard<std::mutex> l(st->m);
            st->jobs[id] = job;
        }
        const bool allow = req.header("x-allow") == "1";
        std::thread([st, job, saved, name, allow, title, ip] {
            try {
                judge(st->p, *job, saved, name, allow, title.empty() ? "제목 없음" : title, ip);
            } catch (const std::exception& e) {
                job->fail_running(e.what());
                job->finish(result_json("error", "판정 실패", e.what(), account(st->p, name)));
            }
        }).detach();
        http::reply(c, "200 OK", "application/json", "{\"job\":\"" + id + "\"}");
    }

    static void handle(const std::shared_ptr<State>& st, SOCKET c, const std::string& ip) {
        http::Request req;
        if (!http::read_request(c, req)) return;
        if (req.method == "OPTIONS") return http::reply(c, "204 No Content", "text/plain", "");
        if (req.path == "/" || req.path == "/index.html")
            return http::send_file(c, st->p.home / L"video-upload-client.html", "", "text/html; charset=utf-8");
        if (req.path == "/api/account") return http::reply(c, "200 OK", "application/json", account_json(account(st->p, http::param(req.query, "name"))));
        if (req.path == "/api/upload" && req.method == "POST") return upload(st, c, req, ip);
        if (req.path.rfind("/api/job/", 0) == 0) {
            std::string rest = req.path.substr(9);
            const size_t slash = rest.find('/');
            const auto job = st->find(rest.substr(0, slash));
            if (!job) return http::reply(c, "404 Not Found", "application/json", "{}");
            if (slash == std::string::npos) return http::reply(c, "200 OK", "application/json", job->to_json());
            rest = rest.substr(slash + 1);
            if (rest == "file") {
                fs::path out;
                {
                    std::lock_guard<std::mutex> l(job->m);
                    out = job->output;
                }
                return out.empty() ? http::reply(c, "404 Not Found", "text/plain", "") : http::send_file(c, out, req.header("range"), "video/mp4");
            }
            if (rest.rfind("image/", 0) == 0) {
                std::string bytes;
                {
                    std::lock_guard<std::mutex> l(job->m);
                    const size_t n = (size_t)std::atoi(rest.c_str() + 6);
                    if (n < job->images.size()) bytes.assign(job->images[n].rgb.begin(), job->images[n].rgb.end());
                }
                return http::reply(c, bytes.empty() ? "404 Not Found" : "200 OK", "application/octet-stream", bytes);
            }
        }
        http::reply(c, "404 Not Found", "text/plain", "");
    }

    http::Listener listener_;
    std::string address_;
};

}  // namespace site
}  // namespace fm
