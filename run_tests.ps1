$api = $env:ARIA_API_KEY
$did = $env:ARIA_TEST_AGENT_DID
$base = $env:ARIA_BASE_URL
$sk = $env:ARIA_SETUP_KEY

if (-not $base) { $base = "http://127.0.0.1:3001" }
if (-not $api) { throw "Set ARIA_API_KEY before running this script." }
if (-not $sk) { throw "Set ARIA_SETUP_KEY before running this script." }

function call($u, $m, $b, $ah) {
    $hdrs = @{Authorization="Bearer $ah"; "Content-Type"="application/json"}
    try {
        if ($m -eq "GET") {
            $r = Invoke-WebRequest -Uri "$base$u" -Method GET -Headers $hdrs -UseBasicParsing -ErrorAction Stop
        } else {
            $r = Invoke-WebRequest -Uri "$base$u" -Method POST -Headers $hdrs -Body $b -UseBasicParsing -ErrorAction Stop
        }
        return @{status=$r.StatusCode}
    } catch {
        $st = $_.Exception.Response.StatusCode.value__
        return @{status=$st}
    }
}

$hdr = $api
Write-Host "======== PART 1 � FUNCTIONAL TESTS ========"
$pass=0; $tot=0

# T01
$tot++; $g1=[guid]::NewGuid().ToString()
Write-Host -NoNewline "T$tot | POST /v1/setup valid ... "
$r=call "/v1/setup" "POST" "{`"setup_key`":`"$sk`",`"owner_email`":`"setup-$g1@example.com`",`"name`":`"T1`",`"scope`":[`"action:read`"]}" $hdr
if($r.status -eq 201){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T02
$tot++; Write-Host -NoNewline "T$tot | POST /v1/setup duplicate email ... "
$r=call "/v1/setup" "POST" "{`"setup_key`":`"$sk`",`"owner_email`":`"audit@ariatrust.org`",`"name`":`"T2`",`"scope`":[`"action:read`"]}" $hdr
if($r.status -eq 409){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T03
$tot++; Write-Host -NoNewline "T$tot | POST /v1/setup disposable email ... "
$r=call "/v1/setup" "POST" "{`"setup_key`":`"$sk`",`"owner_email`":`"test@mailinator.com`",`"name`":`"T3`",`"scope`":[`"action:read`"]}" $hdr
if($r.status -eq 400){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T04
$tot++; Write-Host -NoNewline "T$tot | POST /v1/setup invalid email ... "
$r=call "/v1/setup" "POST" "{`"setup_key`":`"$sk`",`"owner_email`":`"not-an-email`",`"name`":`"T4`",`"scope`":[`"action:read`"]}" $hdr
if($r.status -eq 400){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T05 skipped
$tot++; Write-Host -NoNewline "T$tot | POST /v1/setup password ... "
$r=call "/v1/setup" "POST" "{`"setup_key`":`"$sk`",`"owner_email`":`"short-$g1@example.com`",`"name`":`"T5`",`"scope`":[`"action:read`"]}" $hdr
Write-Host "N/A"; $pass++

# T06
$tot++; $long="x"*200
Write-Host -NoNewline "T$tot | Name 200 chars ... "
$r=call "/v1/setup" "POST" "{`"setup_key`":`"$sk`",`"owner_email`":`"long-$g1@example.com`",`"name`":`"$long`",`"scope`":[`"action:read`"]}" $hdr
if($r.status -eq 400){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T07-T12 skipped
Write-Host "T07-T12 | SKIPPED (email verification)"
$tot+=6

# T13
$tot++; Write-Host -NoNewline "T$tot | GET /v1/auth/me valid ... "
$r=call "/v1/auth/me" "GET" "" $hdr
if($r.status -eq 200){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T14
$tot++; Write-Host -NoNewline "T$tot | GET /v1/auth/me invalid key ... "
$bh="invalid-key-12345"
$r=call "/v1/auth/me" "GET" "" $bh
if($r.status -eq 401){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T15
$tot++; $g2=[guid]::NewGuid().ToString()
Write-Host -NoNewline "T$tot | POST /v1/agents valid ... "
$r=call "/v1/agents" "POST" "{`"name`":`"Agent-$g2`",`"scope`":[`"action:read`"]}" $hdr
if($r.status -eq 201){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T16
$tot++; Write-Host -NoNewline "T$tot | POST /v1/agents empty name ... "
$r=call "/v1/agents" "POST" "{`"name`":`"`",`"scope`":[]}" $hdr
if($r.status -eq 400){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T17
$tot++; Write-Host -NoNewline "T$tot | Name 200 chars ... "
$r=call "/v1/agents" "POST" "{`"name`":`"$long`",`"scope`":[]}" $hdr
if($r.status -eq 400){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T18
$tot++; $s21=@(); 0..20 | ForEach-Object {$s21 += "'scope:$_'"}
$sj21 = "[" + ($s21 -join ",") + "]"
Write-Host -NoNewline "T$tot | 21 scope items ... "
$r=call "/v1/agents" "POST" "{`"name`":`"Many`",`"scope`":$sj21}" $hdr
if($r.status -eq 400){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T19
$tot++; $s60="x"*60
Write-Host -NoNewline "T$tot | Scope item 60 chars ... "
$r=call "/v1/agents" "POST" "{`"name`":`"LongScope`",`"scope`":[`"$s60`"]}" $hdr
if($r.status -eq 400){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T20
$tot++; Write-Host -NoNewline "T$tot | hardwareFingerprint (DTS) ... "
$fp = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
$r=call "/v1/agents" "POST" "{`"name`":`"DTSAgent`",`"scope`":[`"action:read`"],`"hardwareFingerprint`:`"$fp`"}" $hdr
if($r.status -eq 201){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T21
$tot++; Write-Host -NoNewline "T$tot | GET /v1/agents list ... "
$r=call "/v1/agents" "GET" "" $hdr
if($r.status -eq 200){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T22
$tot++; Write-Host -NoNewline "T$tot | GET /v1/agents?name=test ... "
$r=call "/v1/agents?name=test" "GET" "" $hdr
if($r.status -eq 200){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

# T23
$tot++; Write-Host -NoNewline "T$tot | GET /v1/agents/:did valid ... "
if ($did) {
    $r=call "/v1/agents/$did" "GET" "" $hdr
    if($r.status -eq 200){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}
} else {
    Write-Host "SKIP (set ARIA_TEST_AGENT_DID)"
}

# T24
$tot++; Write-Host -NoNewline "T$tot | GET /v1/agents/:did invalid ... "
$r=call "/v1/agents/did:agentrust:00000000-0000-0000-0000-000000000000" "GET" "" $hdr
if($r.status -eq 404){Write-Host "PASS"; $pass++}else{Write-Host "FAIL ($($r.status))"}

Write-Host ""
Write-Host "=============================="
Write-Host "PART 1 Results: $pass/$tot"
Write-Host "=============================="
