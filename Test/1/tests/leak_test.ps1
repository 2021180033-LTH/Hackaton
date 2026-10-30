# 유출 시나리오 시험: 발급한 사본을 여러 방식으로 변형한 뒤 누구의 사본인지 추적되는지 확인한다.
# 사용: pwsh -File tests\leak_test.ps1   (issue로 사본을 3개 이상 발급한 뒤 실행)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root 'ForensicMark.exe'
$ffmpeg = (Get-Content (Join-Path $root 'settings.ini') | Select-String '^ffmpeg=(.+)$').Matches[0].Groups[1].Value
$out = Join-Path $PSScriptRoot 'leaks'
New-Item -ItemType Directory -Force $out | Out-Null

$issued = Import-Csv (Join-Path $root 'data\issued.tsv') -Delimiter "`t" -Encoding utf8
if ($issued.Count -lt 3) { throw 'issue로 사본을 3개 이상 발급한 뒤 실행하세요' }
$A, $B, $C = $issued[0], $issued[1], $issued[2]
$original = (Import-Csv (Join-Path $root 'data\assets.tsv') -Delimiter "`t" -Encoding utf8)[0].source_file

# 이름, 기대 결과(받는 사람 또는 '식별 불가'), ffmpeg 인자
$cases = @(
    @('A_사본그대로',            $A.recipient, @('-i', $A.file, '-c', 'copy')),
    @('B_재압축CRF28_480p',       $B.recipient, @('-i', $B.file, '-vf', 'scale=854:480', '-c:v', 'libx264', '-crf', '28', '-an')),
    @('B_재압축CRF30',            $B.recipient, @('-i', $B.file, '-c:v', 'libx264', '-crf', '30', '-an')),
    @('A_뒤3초만_CRF23',          $A.recipient, @('-ss', '5', '-i', $A.file, '-c:v', 'libx264', '-crf', '23', '-an')),
    @('C_녹화흉내_축소확대_밝기',  $C.recipient, @('-i', $C.file, '-vf', 'scale=960:540,scale=1280:720,eq=brightness=0.03:contrast=1.05', '-c:v', 'libx264', '-crf', '26', '-an')),
    @('C_가장자리5퍼센트_잘라냄',  '식별 불가',   @('-i', $C.file, '-vf', 'crop=iw*0.95:ih*0.95,scale=1280:720', '-c:v', 'libx264', '-crf', '23', '-an')),
    @('A와C_섞기_공모',           '식별 불가',   @('-i', $A.file, '-i', $C.file, '-filter_complex', '[0:v][1:v]blend=all_mode=average', '-c:v', 'libx264', '-crf', '20', '-an')),
    @('표식없는_원본',            '식별 불가',   @('-i', $original, '-c', 'copy'))
)

$rows = foreach ($c in $cases) {
    $name, $expected, $args = $c
    $file = Join-Path $out "$name.mp4"
    & $ffmpeg -v error -y @args $file
    $json = Join-Path $out "$name.json"
    $null = & $exe trace $file --json $json
    $r = Get-Content -Raw -Encoding utf8 $json | ConvertFrom-Json
    $got = if ($r.result -eq 'traced') { $r.recipient } elseif ($r.result -eq 'not_issued') { '발급 기록 없음' } else { '식별 불가' }
    [pscustomobject]@{ 시나리오 = $name; 기대 = $expected; 결과 = $got; 일치 = ($got -eq $expected); 보정비트 = $r.corrected_bits; 신호 = [math]::Round($r.signal_margin, 1) }
}
$rows | Format-Table -AutoSize | Out-String -Width 200
"통과 {0} / {1}" -f @($rows | Where-Object 일치).Count, $rows.Count
$rows | Export-Csv (Join-Path $PSScriptRoot 'leak_results.tsv') -Delimiter "`t" -Encoding utf8 -NoTypeInformation
