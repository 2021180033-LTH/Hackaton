// ForensicMark 명령행: 재생 공개, 표식 확인
//   ForensicMark serve <영상.mp4>            웹 주소로 공개. 재생한 기기마다 전용 표식 사본을 만들고 그 기기의 IP·브라우저·OS·시각을 기록
//   ForensicMark check <영상.mp4> [--json 결과.json]
//   ForensicMark list
//   ForensicMark site [포트]                  FRAME 업로드 사이트 + 업로드 판정기·코드 삽입기 (기본 8090)
//   ForensicMark embed <영상.mp4>            (시험용) 이 PC 이름·IP로 기록하고 표식을 넣어 원본 옆에 저장
#include "site.h"

#include <conio.h>
#include <iostream>

using namespace fm;

static int usage() {
    std::cout << "사용법\n"
                 "  ForensicMark serve <영상.mp4>\n"
                 "  ForensicMark check <영상.mp4> [--json 결과.json]\n"
                 "  ForensicMark list\n"
                 "  ForensicMark site [포트]\n"
                 "  ForensicMark embed <영상.mp4>   (시험용)\n";
    // 탐색기에서 더블클릭해 이 프로그램만의 콘솔 창이 열린 경우: 바로 닫히지 않게 안내 후 대기
    DWORD ids[2];
    if (GetConsoleProcessList(ids, 2) == 1) {
        std::cout << "\n이 프로그램은 명령행용이에요. 창으로 쓰려면 같은 폴더의 MarkTool.exe를 여세요.\n\n아무 키나 누르면 닫혀요.";
        _getwch();
    }
    return 2;
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) return usage();
    const std::wstring cmd = argv[1];
    try {
        const Paths p = paths();
        if (cmd == L"site") {
            site::SiteServer server;
            const std::string url = server.start(p, argc >= 3 ? _wtoi(argv[2]) : 8090);
            std::cout << "FRAME 업로드 사이트  " << url
                      << "\n  영상을 올리면 코드 확인 → 원작자 허용 확인 → 등록·차단을 판정해요. 끝내려면 Ctrl+C\n";
            for (;;) Sleep(1000);
        }
        if (cmd == L"serve" && argc >= 3) {
            PlayServer server;
            size_t shown = issues(p).size();
            std::mutex m;
            const std::string url = server.start(p, argv[2], [&] {
                std::lock_guard<std::mutex> l(m);
                const auto all = issues(p);
                for (; shown < all.size(); ++shown)
                    std::cout << "  재생 " << all[shown].viewer << "  " << all[shown].ip << "  " << all[shown].device << "  " << all[shown].issued_at << "\n";
            });
            std::cout << "공개 중 (고유 코드 " << server.asset_id() << ")  " << url << "\n  재생한 기기마다 전용 사본을 만들고 IP·기기·시각을 기록해요. 끝내려면 Ctrl+C\n";
            for (;;) Sleep(1000);
        }
        if (cmd == L"embed" && argc >= 3) {
            const Asset a = register_asset(p, argv[2]);
            const Issue i = issue_copy(p, a.id, "", computer_name(), local_ipv4(), [](int n) {
                if (n % 30 == 0) std::cout << "  " << n << " 프레임\r" << std::flush;
            }, argv[2]);
            std::cout << "표식 넣기 완료  고유 코드 " << i.asset << " / 식별 번호 " << i.viewer << "  (기기 " << i.device << " · IP " << i.ip
                      << ")\n  " << i.file << "\n";
            return 0;
        }
        if ((cmd == L"check" || cmd == L"trace") && argc >= 3) {
            const fs::path video = argv[2];
            const Verdict v = trace(p, video);
            if (v.result == "traced")
                std::cout << "표식 있음  고유 코드 " << v.issue.asset << " / 식별 번호 " << v.issue.viewer << "\n  기기 " << v.issue.device << "\n  IP "
                          << v.issue.ip << (v.issue.device.find(" · ") != std::string::npos ? "\n  재생 시각 " : "\n  넣은 시각 ") << v.issue.issued_at << "\n"
                          << (v.issue.recipient.empty() ? "" : "  브라우저 정보 " + v.issue.recipient + "\n");
            else if (v.result == "not_issued")
                std::cout << "표식은 진짜지만 기록에 없는 번호예요 (고유 코드 " << v.issue.asset << " / 식별 번호 " << v.issue.viewer << ")\n";
            else if (v.result == "original_only")
                std::cout << "원본은 찾았지만 식별 번호는 읽지 못했어요 (원본 고유 코드 " << v.match.asset << ")\n";
            else
                std::cout << "표식 없음: 읽을 수 있는 표식을 찾지 못했어요\n";
            if (v.detection.transformed) std::cout << "  되돌린 가공 " << describe(v.detection.geometry) << "\n";
            if (!v.match.asset.empty())
                std::cout << "  지문 비교 원본 " << v.match.asset << " · 유사도 " << std::fixed << std::setprecision(0) << v.match.similarity * 100 << "%\n";
            std::cout << "  검사 프레임 " << v.detection.frames << " · 보정한 비트 " << v.detection.corrected_bits << " · 신호 " << std::fixed
                      << std::setprecision(1) << v.detection.margin << "\n";
            for (int i = 3; i + 1 < argc; ++i)
                if (std::wstring(argv[i]) == L"--json") std::ofstream(argv[i + 1], std::ios::binary) << verdict_json(v, video);
            return v.result == "traced" ? 0 : 1;
        }
        // 이전 시험 스크립트(tests\leak_test.ps1)와의 호환용
        if (cmd == L"register" && argc >= 3) {
            const Asset a = register_asset(p, argv[2]);
            std::cout << "고유 코드 " << a.id << "  (" << a.file << ")\n";
            return 0;
        }
        if (cmd == L"issue" && argc >= 3) {
            const Issue i = issue_copy(p, utf8(argv[2]), argc > 3 ? utf8(argv[3]) : "", argc > 4 ? utf8(argv[4]) : computer_name(),
                                       argc > 5 ? utf8(argv[5]) : local_ipv4());
            std::cout << "표식 넣기 완료  식별 번호 " << i.viewer << "\n  " << i.file << "\n";
            return 0;
        }
        if (cmd == L"list") {
            for (const auto& i : issues(p))
                std::cout << "  " << i.viewer << "  " << i.asset << "  " << i.device << "  " << i.ip << "  " << i.issued_at << "  " << i.file << "\n";
            return 0;
        }
        return usage();
    } catch (const std::exception& e) {
        std::cout << "오류: " << e.what() << "\n";
        return 3;
    }
}
