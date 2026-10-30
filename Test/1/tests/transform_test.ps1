# 표식 영상을 여러 방식으로 가공한 뒤 ForensicMark check로 다시 찾는 시험
# 사용: powershell -File tests\transform_test.ps1 [표식영상.mp4]   (기본: samples\luma_courier_8s_표식_3b449b.mp4)
param([string]$Marked = "")
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'ForensicMark.exe'
$ffmpeg = (Get-Content (Join-Path $root 'settings.ini') | Where-Object { $_ -like 'ffmpeg=*' }) -replace '^ffmpeg=', ''
if (-not $Marked) { $Marked = Join-Path $root 'samples\luma_courier_8s_표식_3b449b.mp4' }
$original = Join-Path $root 'samples\luma_courier_8s.mp4'
$expect = ([regex]'_표식_([0-9a-f]{6})').Match($Marked).Groups[1].Value
$dir = Join-Path $root 'tests\transform'
New-Item -ItemType Directory -Force $dir | Out-Null

# 이름, 입력, ffmpeg 필터(없으면 재압축만), 기대 결과(식별 번호 / original_only / unidentified)
$cases = @(
    @('01_축소50%_640x360',            $Marked,   'scale=640:360',                                    $expect),
    @('02_축소25%_320x180',            $Marked,   'scale=320:180',                                    $expect),
    @('03_확대_1920x1080',             $Marked,   'scale=1920:1080',                                  $expect),
    @('04_가로로_늘림_1600x720',       $Marked,   'scale=1600:720',                                   $expect),
    @('05_세로로_찌그러뜨림_1280x540', $Marked,   'scale=1280:540',                                   $expect),
    @('06_4대3으로_찌그러뜨림_960x720', $Marked,  'scale=960:720',                                    $expect),
    @('07_축소후_다시확대',            $Marked,   'scale=480:270,scale=1280:720',                     $expect),
    @('08_위아래_검은띠_추가',         $Marked,   'pad=1280:960:0:120',                               $expect),
    @('09_좌우반전',                   $Marked,   'hflip',                                            $expect),
    @('10_상하반전',                   $Marked,   'vflip',                                            $expect),
    @('11_좌우상하_모두반전',          $Marked,   'hflip,vflip',                                      $expect),
    @('12_가장자리5%_자르기',          $Marked,   'crop=iw*0.95:ih*0.95,scale=1280:720',              $expect),
    @('13_가장자리10%_자르기',         $Marked,   'crop=iw*0.9:ih*0.9',                               $expect),
    @('13b_가장자리20%_자르기',        $Marked,   'crop=iw*0.8:ih*0.8',                               $expect),
    @('14_오른쪽만_6%_자르기',         $Marked,   'crop=iw*0.94:ih:0:0',                              $expect),
    @('15_1.5배속',                    $Marked,   'setpts=PTS/1.5',                                   $expect),
    @('16_2도_회전',                   $Marked,   'rotate=2*PI/180',                                  $expect),
    @('17_세로쇼츠_반전_검은띠',       $Marked,   'hflip,scale=1080:-2,pad=1080:1920:0:(oh-ih)/2',    $expect),
    @('18_표식없는_원본',              $original, '',                                                 'original_only'),
    @('19_전혀_다른_영상',             'testsrc', '',                                                 'unidentified')
)

$rows = @()
foreach ($c in $cases) {
    $name, $src, $vf, $want = $c
    $out = Join-Path $dir "$name.mp4"
    if ($src -eq 'testsrc') {
        & $ffmpeg -v error -y -f lavfi -i 'testsrc2=size=1280x720:rate=30:duration=8' -c:v libx264 -crf 23 -pix_fmt yuv420p $out
    } elseif ($vf) {
        & $ffmpeg -v error -y -i $src -vf $vf -an -c:v libx264 -crf 23 -pix_fmt yuv420p $out
    } else {
        & $ffmpeg -v error -y -i $src -an -c:v libx264 -crf 23 -pix_fmt yuv420p $out
    }
    $json = Join-Path $dir "$name.json"
    $t = Measure-Command { & $exe check $out --json $json | Out-Null }
    $r = Get-Content $json -Raw -Encoding UTF8 | ConvertFrom-Json
    $got = if ($r.result -eq 'traced' -or $r.result -eq 'not_issued') { $r.viewer_id } else { $r.result }
    $rows += [pscustomobject]@{
        가공 = $name
        결과 = if ($got -eq $want) { "✅ $got" } else { "❌ $got (기대 $want)" }
        되돌린가공 = $r.undone_edits
        지문유사도 = if ($r.fingerprint_similarity) { '{0:P0}' -f [double]$r.fingerprint_similarity } else { '' }
        신호 = '{0:N1}' -f [double]$r.signal_margin
        초 = '{0:N1}' -f $t.TotalSeconds
    }
    Remove-Item -LiteralPath $out
    Write-Host ("{0,-32} {1}" -f $name, $rows[-1].결과)
}
$rows | Export-Csv (Join-Path $dir 'results.tsv') -Delimiter "`t" -NoTypeInformation -Encoding UTF8
$pass = ($rows | Where-Object { $_.결과 -like '✅*' }).Count
Write-Host "통과 $pass / $($rows.Count)"
$rows | Format-Table -AutoSize | Out-String -Width 200
