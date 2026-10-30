// 표식 도구: ① 영상을 웹 주소로 공개해 재생한 기기마다 전용 표식 사본을 주고 그 기기의 IP·기기·시각을 기록,
//            ② 아무 영상이나 표식을 확인해 어느 기기에서 재생한 사본인지 찾는다
#include "server.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

#include <memory>
#include <thread>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace fm;

enum : int { IDC_PICK_SERVE = 100, IDC_SERVE, IDC_COPY, IDC_FOLDER, IDC_PICK_CHECK, IDC_LIST };
constexpr UINT WM_SERVER_UPDATE = WM_APP + 1, WM_SERVER_STARTED = WM_APP + 2, WM_CHECK_DONE = WM_APP + 3;
// 96 DPI 기준 배치
constexpr int SERVE_TOP = 92, SERVE_H = 216, CHECK_TOP = SERVE_TOP + SERVE_H + 16, CHECK_H = 200, LIST_TOP = CHECK_TOP + CHECK_H + 40;
const COLORREF BG = RGB(18, 24, 32), CARD = RGB(28, 37, 48), FG = RGB(232, 238, 242), MUTED = RGB(150, 166, 178),
               GREEN = RGB(88, 214, 141), ORANGE = RGB(245, 166, 35), RED = RGB(240, 98, 98);

struct CheckResult {
    bool ok = false;
    std::wstring file, error;
    Verdict verdict;
};

HWND g_wnd = nullptr, g_list = nullptr;
HFONT g_title, g_head, g_body, g_small;
HBRUSH g_bg, g_card;
UINT g_dpi = 96;
Paths g_paths;

// ① 재생 공개 상태
std::wstring g_source;
PlayServer g_server;
bool g_starting = false;
std::wstring g_serve_error;

// ② 확인 상태
bool g_checking = false;
std::unique_ptr<CheckResult> g_check;
std::wstring g_check_file;

int S(int v) { return MulDiv(v, (int)g_dpi, 96); }
HWND ctl(int id) { return GetDlgItem(g_wnd, id); }

HFONT make_font(int pt, int weight) {
    return CreateFontW(-MulDiv(pt, (int)g_dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Malgun Gothic");
}

std::wstring name_of(const std::wstring& path) { return fs::path(path).filename().wstring(); }

void update_buttons() {
    const bool on = g_server.running();
    EnableWindow(ctl(IDC_PICK_SERVE), !on && !g_starting);
    EnableWindow(ctl(IDC_SERVE), !g_source.empty() && !g_starting);
    SetWindowTextW(ctl(IDC_SERVE), on ? L"공개 중지" : L"공개 시작");
    EnableWindow(ctl(IDC_COPY), on);
    EnableWindow(ctl(IDC_PICK_CHECK), !g_checking);
}

// 기록 한 줄이 재생 서버에서 온 것인지 (재생 기록의 기기 칸은 "OS · 브라우저" 형식)
bool from_playback(const Issue& i) { return i.device.find(" · ") != std::string::npos; }

void fill_list() {
    SendMessageW(g_list, LVM_DELETEALLITEMS, 0, 0);
    const auto all = assets(g_paths);
    int row = 0;
    for (const auto& i : issues(g_paths)) {
        std::wstring source = name_of(wide(i.source));
        if (i.source.empty())
            for (const auto& a : all)
                if (a.id == i.asset) source = name_of(wide(a.file));
        const std::wstring cols[] = {wide(i.viewer), wide(i.ip), from_playback(i) ? wide(i.device) : wide(i.device) + L" (직접 넣음)", wide(i.issued_at),
                                     source, name_of(wide(i.file))};
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.pszText = const_cast<wchar_t*>(cols[0].c_str());
        SendMessageW(g_list, LVM_INSERTITEMW, 0, (LPARAM)&item);
        for (int c = 1; c < 6; ++c) {
            item.iSubItem = c;
            item.pszText = const_cast<wchar_t*>(cols[c].c_str());
            SendMessageW(g_list, LVM_SETITEMTEXTW, row, (LPARAM)&item);
        }
        ++row;
    }
    if (row) SendMessageW(g_list, LVM_ENSUREVISIBLE, row - 1, FALSE);
}

std::wstring pick_file(HWND owner) {
    wchar_t file[MAX_PATH * 4] = L"";
    OPENFILENAMEW of{};
    of.lStructSize = sizeof(of);
    of.hwndOwner = owner;
    of.lpstrFilter = L"영상 (*.mp4;*.mov;*.mkv;*.webm)\0*.mp4;*.mov;*.mkv;*.webm\0모든 파일\0*.*\0";
    of.lpstrFile = file;
    of.nMaxFile = (DWORD)std::size(file);
    of.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    return GetOpenFileNameW(&of) ? file : L"";
}

void set_source(const std::wstring& file) {
    if (g_server.running() || g_starting) return;
    g_source = file;
    g_serve_error.clear();
    update_buttons();
    InvalidateRect(g_wnd, nullptr, FALSE);
}

// ① 공개 시작/중지. 시작할 때 원본 등록과 지문 저장을 하므로 별도 스레드에서
void toggle_server() {
    if (g_server.running()) {
        g_server.stop();
        update_buttons();
        InvalidateRect(g_wnd, nullptr, FALSE);
        return;
    }
    if (g_source.empty() || g_starting) return;
    g_starting = true;
    g_serve_error.clear();
    update_buttons();
    InvalidateRect(g_wnd, nullptr, FALSE);
    const std::wstring source = g_source;
    std::thread([source] {
        std::wstring* error = nullptr;
        try {
            g_server.start(g_paths, source, [] { PostMessageW(g_wnd, WM_SERVER_UPDATE, 0, 0); });
        } catch (const std::exception& e) {
            error = new std::wstring(wide(e.what()));
        }
        PostMessageW(g_wnd, WM_SERVER_STARTED, 0, (LPARAM)error);
    }).detach();
}

void copy_address() {
    const std::wstring s = wide(g_server.address());
    if (!OpenClipboard(g_wnd)) return;
    EmptyClipboard();
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, (s.size() + 1) * sizeof(wchar_t));
    memcpy(GlobalLock(mem), s.c_str(), (s.size() + 1) * sizeof(wchar_t));
    GlobalUnlock(mem);
    SetClipboardData(CF_UNICODETEXT, mem);
    CloseClipboard();
}

// ② 아무 영상이나 표식 확인
void start_check(const std::wstring& file) {
    if (g_checking || file.empty()) return;
    g_checking = true;
    g_check.reset();
    g_check_file = file;
    update_buttons();
    InvalidateRect(g_wnd, nullptr, FALSE);
    std::thread([file] {
        auto r = std::make_unique<CheckResult>();
        r->file = file;
        try {
            r->verdict = trace(g_paths, file);
            r->ok = true;
        } catch (const std::exception& e) {
            r->error = wide(e.what());
        }
        PostMessageW(g_wnd, WM_CHECK_DONE, 0, (LPARAM)r.release());
    }).detach();
}

void text(HDC dc, int x, int y, int w, int h, const std::wstring& s, HFONT font, COLORREF color, UINT flags = DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS | DT_VCENTER) {
    RECT r{x, y, x + w, y + h};
    SelectObject(dc, font);
    SetTextColor(dc, color);
    DrawTextW(dc, s.c_str(), -1, &r, flags | DT_NOPREFIX);
}

void card(HDC dc, int x, int y, int w, int h) {
    HGDIOBJ ob = SelectObject(dc, g_card), op = SelectObject(dc, GetStockObject(NULL_PEN));
    RoundRect(dc, x, y, x + w, y + h, S(16), S(16));
    SelectObject(dc, ob);
    SelectObject(dc, op);
}

std::wstring percent(double v) { return std::to_wstring((int)std::lround(v * 100)) + L"%"; }

// 확인 결과 한 줄 요약
std::wstring verdict_line(const Verdict& v, COLORREF& color) {
    if (v.result == "traced") {
        color = GREEN;
        return L"● 표식 있음 · 식별 번호 " + wide(v.issue.viewer) + L" (고유 코드 " + wide(v.issue.asset) + L")";
    }
    if (v.result == "not_issued") {
        color = ORANGE;
        return L"● 표식 있음 · 식별 번호 " + wide(v.issue.viewer) + L" · 이 PC의 기록에는 없는 번호";
    }
    if (v.result == "original_only") {
        color = ORANGE;
        return L"● 원본 확인 · 고유 코드 " + wide(v.match.asset) + L" (지문 유사도 " + percent(v.match.similarity) + L") · 식별 번호는 읽지 못함";
    }
    color = MUTED;
    return L"● 표식 없음 · 등록된 원본과도 다른 영상";
}

std::wstring verdict_detail(const Verdict& v) {
    const std::wstring source = name_of(wide(v.issue.source.empty() ? v.asset.file : v.issue.source));
    if (v.result == "traced")
        return (from_playback(v.issue) ? L"재생한 IP " : L"IP ") + wide(v.issue.ip) + L" · 기기 " + wide(v.issue.device) +
               (from_playback(v.issue) ? L" · 재생 시각 " : L" · 넣은 시각 ") + wide(v.issue.issued_at) + L" · 원본 " + source;
    if (v.result == "not_issued") return L"비밀키로 만든 진짜 표식이지만, 이 PC에는 해당 기록이 없어요";
    if (v.result == "original_only") return L"원본 " + source + L"과 같은 영상이에요. 표식이 없는 원본이거나, 아주 작게 줄이는 등으로 표식이 지워졌어요";
    return L"등록된 원본 중 비슷한 영상이 없어요" + (v.match.similarity > 0 ? L" (가장 높은 지문 유사도 " + percent(v.match.similarity) + L")" : L"");
}

void paint(HDC dc, const RECT& rc) {
    FillRect(dc, &rc, g_bg);
    SetBkMode(dc, TRANSPARENT);
    const int m = S(24), w = rc.right - 2 * m, x = m + S(24), cw = w - S(48);
    text(dc, m, S(12), w, S(40), L"표식 도구", g_title, FG);
    text(dc, m, S(54), w, S(24), L"영상을 재생한 기기마다 다른 표식을 보이지 않게 넣고, 나중에 발견된 영상이 어느 기기에서 재생한 것인지 찾습니다.", g_small, MUTED);

    // ① 재생 공개
    const int sy = S(SERVE_TOP);
    card(dc, m, sy, w, S(SERVE_H));
    text(dc, x, sy + S(14), S(300), S(28), L"① 재생 공개", g_head, FG);
    text(dc, x + S(180), sy + S(58), cw - S(180), S(30), g_source.empty() ? L"공개할 영상을 고르거나 이 칸에 끌어 놓으세요" : name_of(g_source), g_body,
         g_source.empty() ? MUTED : FG);
    if (g_starting) {
        text(dc, x, sy + S(148), cw, S(30), L"원본을 등록하고 서버를 여는 중…", g_body, FG);
    } else if (!g_serve_error.empty()) {
        text(dc, x, sy + S(148), cw, S(30), L"공개 실패: " + g_serve_error, g_body, RED);
    } else if (g_server.running()) {
        const auto [ready, wait] = g_server.counts();
        text(dc, x, sy + S(146), cw, S(32), L"재생 주소  " + wide(g_server.address()), g_head, GREEN);
        text(dc, x, sy + S(180), cw, S(24),
             L"재생한 기기 " + std::to_wstring(ready) + L"대" + (wait ? L" · 사본 준비 중 " + std::to_wstring(wait) + L"대" : L"") +
                 L" · 같은 와이파이의 휴대폰·PC에서 이 주소를 열면 그 기기 전용 사본이 재생되고 IP·기기·시각이 기록돼요",
             g_small, MUTED);
    } else {
        text(dc, x, sy + S(148), cw, S(30), L"공개하면 재생 주소가 생겨요. 재생한 기기마다 전용 표식 사본을 만들고 그 기기의 IP·기기·시각을 기록해요.",
             g_small, MUTED);
    }

    // ② 확인
    const int cy = S(CHECK_TOP);
    card(dc, m, cy, w, S(CHECK_H));
    text(dc, x, cy + S(14), S(300), S(28), L"② 표식 확인", g_head, FG);
    text(dc, x + S(180), cy + S(58), cw - S(180), S(30), g_check_file.empty() ? L"확인할 영상을 고르거나 이 칸에 끌어 놓으세요" : name_of(g_check_file), g_body,
         g_check_file.empty() ? MUTED : FG);
    if (g_checking) {
        text(dc, x, cy + S(104), cw, S(30), L"표식을 읽는 중… (반전·잘라내기 등 가공된 영상은 되돌려 보느라 몇 초 더 걸려요)", g_body, FG);
    } else if (g_check && !g_check->ok) {
        text(dc, x, cy + S(104), cw, S(30), L"확인 실패: " + g_check->error, g_body, RED);
    } else if (g_check) {
        COLORREF color = MUTED;
        const auto& v = g_check->verdict;
        const std::wstring line = verdict_line(v, color);  // 색을 먼저 정한 뒤 그린다 (인자 평가 순서에 기대지 않음)
        text(dc, x, cy + S(100), cw, S(34), line, g_head, color);
        text(dc, x, cy + S(136), cw, S(26), verdict_detail(v), g_body, FG);
        wchar_t meta[96];
        swprintf_s(meta, L"검사 %d프레임 · 신호 %.1f (표식 없는 영상은 보통 15 이하)", v.detection.frames, v.detection.margin);
        std::wstring info = meta;
        if (v.detection.transformed) info += L" · 되돌린 가공: " + wide(describe(v.detection.geometry));
        if (v.result == "traced" && v.match.similarity >= FP_MATCH) info += L" · 지문 유사도 " + percent(v.match.similarity);
        text(dc, x, cy + S(166), cw, S(22), info, g_small, MUTED);
    }
    text(dc, m, S(LIST_TOP - 26), w, S(22), L"재생 기록 (기기마다 한 줄)", g_small, MUTED);
}

void layout() {
    RECT rc;
    GetClientRect(g_wnd, &rc);
    const int m = S(24), w = rc.right - 2 * m, x = m + S(24);
    const int sy = S(SERVE_TOP), cy = S(CHECK_TOP);
    MoveWindow(ctl(IDC_PICK_SERVE), x, sy + S(56), S(160), S(34), TRUE);
    MoveWindow(ctl(IDC_SERVE), x, sy + S(98), S(160), S(38), TRUE);
    MoveWindow(ctl(IDC_COPY), x + S(172), sy + S(98), S(130), S(38), TRUE);
    MoveWindow(ctl(IDC_FOLDER), x + S(314), sy + S(98), S(130), S(38), TRUE);
    MoveWindow(ctl(IDC_PICK_CHECK), x, cy + S(56), S(160), S(34), TRUE);
    const int top = S(LIST_TOP);
    MoveWindow(g_list, m, top, w, rc.bottom - top - m, TRUE);
}

void create_fonts() {
    for (HFONT f : {g_title, g_head, g_body, g_small})
        if (f) DeleteObject(f);
    g_title = make_font(20, FW_BOLD);
    g_head = make_font(13, FW_BOLD);
    g_body = make_font(11, FW_NORMAL);
    g_small = make_font(9, FW_NORMAL);
    for (int id : {IDC_PICK_SERVE, IDC_SERVE, IDC_COPY, IDC_FOLDER, IDC_PICK_CHECK}) SendMessageW(ctl(id), WM_SETFONT, (WPARAM)g_body, TRUE);
    SendMessageW(g_list, WM_SETFONT, (WPARAM)g_small, TRUE);
}

LRESULT CALLBACK proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_wnd = h;
        g_dpi = GetDpiForWindow(h);
        auto button = [h](const wchar_t* label, int id) {
            CreateWindowW(L"BUTTON", label, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)(INT_PTR)id, nullptr, nullptr);
        };
        button(L"영상 선택…", IDC_PICK_SERVE);
        button(L"공개 시작", IDC_SERVE);
        button(L"주소 복사", IDC_COPY);
        button(L"사본 폴더", IDC_FOLDER);
        button(L"영상 선택…", IDC_PICK_CHECK);
        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL, 0, 0, 0, 0, h, (HMENU)IDC_LIST, nullptr, nullptr);
        SendMessageW(g_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        const std::pair<const wchar_t*, int> cols[] = {{L"식별 번호", 80}, {L"IP", 120}, {L"기기", 170}, {L"시각", 140}, {L"원본", 160}, {L"사본 파일", 220}};
        for (int i = 0; i < 6; ++i) {
            LVCOLUMNW c{};
            c.mask = LVCF_TEXT | LVCF_WIDTH;
            c.pszText = const_cast<wchar_t*>(cols[i].first);
            c.cx = S(cols[i].second);
            SendMessageW(g_list, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
        }
        create_fonts();
        fill_list();
        update_buttons();
        DragAcceptFiles(h, TRUE);
        return 0;
    }
    case WM_SIZE: layout(); InvalidateRect(h, nullptr, FALSE); return 0;
    case WM_DPICHANGED: {
        g_dpi = HIWORD(wp);
        create_fonts();
        const RECT* r = (RECT*)lp;
        SetWindowPos(h, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER);
        return 0;
    }
    case WM_DROPFILES: {  // 위쪽 칸에 놓으면 ① 공개할 영상, 아래쪽 칸에 놓으면 ② 확인
        wchar_t file[MAX_PATH * 4];
        POINT pt{};
        DragQueryFileW((HDROP)wp, 0, file, (UINT)std::size(file));
        DragQueryPoint((HDROP)wp, &pt);
        DragFinish((HDROP)wp);
        if (pt.y < S(CHECK_TOP)) set_source(file);
        else start_check(file);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_PICK_SERVE: {
            const std::wstring f = pick_file(h);
            if (!f.empty()) set_source(f);
            break;
        }
        case IDC_SERVE: toggle_server(); break;
        case IDC_COPY: copy_address(); break;
        case IDC_FOLDER:
            fs::create_directories(g_paths.issued);
            ShellExecuteW(h, L"open", g_paths.issued.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        case IDC_PICK_CHECK: start_check(pick_file(h)); break;
        default: break;
        }
        return 0;
    case WM_SERVER_STARTED: {
        std::unique_ptr<std::wstring> error((std::wstring*)lp);
        g_starting = false;
        if (error) g_serve_error = *error;
        fill_list();
        update_buttons();
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_SERVER_UPDATE:
        fill_list();
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_CHECK_DONE:
        g_check.reset((CheckResult*)lp);
        g_checking = false;
        update_buttons();
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc;
        GetClientRect(h, &rc);
        HDC mem = CreateCompatibleDC(dc);
        HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        HGDIOBJ old = SelectObject(mem, bmp);
        paint(mem, rc);
        BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_CLOSE:
        if (g_starting) return 0;
        g_server.stop();
        break;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    default: break;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    g_paths = paths();
    g_bg = CreateSolidBrush(BG);
    g_card = CreateSolidBrush(CARD);
    WNDCLASSW wc{};
    wc.lpfnWndProc = proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.lpszClassName = L"ForensicMarkTool";
    RegisterClassW(&wc);
    g_dpi = GetDpiForSystem();
    HWND h = CreateWindowW(wc.lpszClassName, L"표식 도구 · ForensicMark", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, S(1040), S(860), nullptr,
                           nullptr, inst, nullptr);
    ShowWindow(h, show);
    int argc = 0;  // 영상을 실행 파일 아이콘에 끌어 놓으면 ① 공개할 영상으로 바로 선택
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc > 1) set_source(argv[1]);
    LocalFree(argv);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
