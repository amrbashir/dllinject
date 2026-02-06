#!/usr/bin/env pwsh

param(
    [string]$SolutionPath = "$PSScriptRoot\inject-shellcode\inject-shellcode.sln",
    [string]$MainCppPath = "$PSScriptRoot\main.cpp"
)

$ErrorActionPreference = "Stop"

function Find-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
        if ($msbuild -and (Test-Path $msbuild)) { return $msbuild }
    }
    
    $paths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    )
    
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    throw "MSBuild not found. Install VS2022+."
}

function Build-Project {
    param([string]$MSBuildPath, [string]$Solution, [string]$Platform)
    Write-Host "Building Release|$Platform..." -ForegroundColor Cyan
    & $MSBuildPath $Solution "/p:Configuration=Release" "/p:Platform=$Platform" "/verbosity:minimal" "/nologo"
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
    Write-Host "Build successful!" -ForegroundColor Green
}

function Get-Shellcode {
    param([string]$ExePath)
    Write-Host "Extracting from $ExePath..." -ForegroundColor Yellow
    
    $bytes = [System.IO.File]::ReadAllBytes($ExePath)
    $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
    $is64 = ([BitConverter]::ToUInt16($bytes, $e_lfanew + 4)) -eq 0x8664
    
    $optHeader = $e_lfanew + 24
    $optHeaderMagic = [BitConverter]::ToUInt16($bytes, $optHeader)
    $isPE32Plus = ($optHeaderMagic -eq 0x20b)
    $optHeaderSize = if ($isPE32Plus) { 240 } else { 224 }
    $sectTable = $optHeader + $optHeaderSize
    $numSections = [BitConverter]::ToUInt16($bytes, $e_lfanew + 6)
    $exportRVAOffset = if ($isPE32Plus) { 112 } else { 96 }
    $exportRVA = [BitConverter]::ToUInt32($bytes, $optHeader + $exportRVAOffset)
    
    # Parse sections
    $sections = for ($i = 0; $i -lt $numSections; $i++) {
        $off = $sectTable + ($i * 40)
        [PSCustomObject]@{
            Name = [Text.Encoding]::ASCII.GetString($bytes, $off, 8).TrimEnd("`0")
            VA = [BitConverter]::ToUInt32($bytes, $off + 12)
            VirtualSize = [BitConverter]::ToUInt32($bytes, $off + 8)
            Raw = [BitConverter]::ToUInt32($bytes, $off + 20)
        }
    }
    
    Write-Host "Sections found:" -ForegroundColor Gray
    $sections | ForEach-Object { Write-Host "  $($_.Name): VA=$($_.VA), VSize=$($_.VirtualSize), Raw=$($_.Raw)" -ForegroundColor Gray }
    Write-Host "Export RVA: $exportRVA" -ForegroundColor Gray
    
    # Find export directory
    $expSect = $sections | Where-Object { 
        $exportRVA -ge $_.VA -and 
        $exportRVA -lt ($_.VA + [Math]::Max($_.VirtualSize, $_.Raw)) 
    } | Select-Object -First 1
    
    if (-not $expSect) {
        throw "Could not find section containing export directory at RVA $exportRVA"
    }
    
    Write-Host "Export section: $($expSect.Name)" -ForegroundColor Gray
    $expOff = $expSect.Raw + ($exportRVA - $expSect.VA)
    
    $numNames = [BitConverter]::ToUInt32($bytes, $expOff + 24)
    $funcTableRVA = [BitConverter]::ToUInt32($bytes, $expOff + 28)
    $nameTableRVA = [BitConverter]::ToUInt32($bytes, $expOff + 32)
    $ordTableRVA = [BitConverter]::ToUInt32($bytes, $expOff + 36)
    
    Write-Host "Export dir: numNames=$numNames, funcTable=$funcTableRVA, nameTable=$nameTableRVA, ordTable=$ordTableRVA" -ForegroundColor Gray
    
    # Helper function to convert RVA to file offset
    function RvaToOffset($Rva) {
        $sect = $sections | Where-Object { $Rva -ge $_.VA -and $Rva -lt ($_.VA + [Math]::Max($_.VirtualSize, $_.Raw)) } | Select-Object -First 1
        if (-not $sect) { throw "RVA $Rva not found in any section" }
        return $sect.Raw + ($Rva - $sect.VA)
    }
    
    # Find InjectShellcode (handle C++ mangled names)
    $funcAddr = $null
    $foundOrd = $null
    for ($i = 0; $i -lt $numNames; $i++) {
        $nRVA = [BitConverter]::ToUInt32($bytes, (RvaToOffset $nameTableRVA) + ($i * 4))
        $nameOff = RvaToOffset $nRVA
        # Read until null terminator
        $nameBytes = @()
        $j = 0
        while ($bytes[$nameOff + $j] -ne 0 -and $j -lt 256) {
            $nameBytes += $bytes[$nameOff + $j]
            $j++
        }
        $name = [Text.Encoding]::ASCII.GetString($nameBytes)
        Write-Host "  Export[$i]: $name" -ForegroundColor DarkGray
        # Check for exact match or mangled name containing InjectShellcode
        if ($name -eq "InjectShellcode" -or $name -like "*InjectShellcode*") {
            $foundOrd = [BitConverter]::ToUInt16($bytes, (RvaToOffset $ordTableRVA) + ($i * 2))
            $funcAddr = [BitConverter]::ToUInt32($bytes, (RvaToOffset $funcTableRVA) + ($foundOrd * 4))
            Write-Host "  Found! Ordinal=$foundOrd, FuncRVA=$funcAddr" -ForegroundColor Green
            break
        }
    }
    
    if (-not $funcAddr) {
        throw "Function 'InjectShellcode' not found in exports"
    }
    
    # Extract function bytes
    $fSect = $sections | Where-Object { 
        $funcAddr -ge $_.VA -and 
        $funcAddr -lt ($_.VA + [Math]::Max($_.VirtualSize, $_.Raw))
    } | Select-Object -First 1
    
    if (-not $fSect) {
        throw "Could not find section containing function at RVA $funcAddr"
    }
    
    Write-Host "Function section: $($fSect.Name)" -ForegroundColor Gray
    $fOff = $fSect.Raw + ($funcAddr - $fSect.VA)
    Write-Host "Function file offset: $fOff" -ForegroundColor Gray
    
    # Read up to 4KB from function start
    $maxRead = [Math]::Min(4096, $bytes.Length - $fOff)
    $fBytes = $bytes[$fOff..($fOff + $maxRead - 1)]
    
    # Find function end: look for pop ebp (5D) followed by ret 4 (C2 04 00) or ret (C3)
    $end = $fBytes.Length - 1
    for ($i = 0; $i -lt $fBytes.Length - 3; $i++) {
        # Check for ret 4: 5D C2 04 00 (pop ebp; ret 4)
        if ($fBytes[$i] -eq 0x5D -and $fBytes[$i+1] -eq 0xC2 -and $fBytes[$i+2] -eq 0x04 -and $fBytes[$i+3] -eq 0x00) {
            $end = $i + 3
            break
        }
        # Check for ret: C3 or C2 XX XX
        if ($fBytes[$i] -eq 0xC3 -and $i -gt 100) {
            # Make sure it's after pop ebp (5D) for x86 or pop rbx/etc for x64
            if ($fBytes[$i-1] -eq 0x5D -or $fBytes[$i-1] -eq 0xC3) {
                $end = $i
                break
            }
        }
    }
    
    Write-Host "Extracted $($end + 1) bytes (found ret at offset $end)" -ForegroundColor Green
    return $fBytes[0..$end]
}

function Format-Bytes {
    param([byte[]]$Bytes)
    $lines = @(); $line = "	`""; $n = 0
    foreach ($b in $Bytes) {
        $line += "\x{0:X2}" -f $b; $n++
        if ($n % 15 -eq 0 -and $n -lt $Bytes.Length) {
            $lines += $line + '"' ; $line = "	`""
        }
    }
    $lines += $line + '";' ;
    return $lines -join "`r`n"
}

# Main
Write-Host "=== Shellcode Generator ===" -ForegroundColor Magenta
$SolutionPath = Resolve-Path $SolutionPath
$MainCppPath = Resolve-Path $MainCppPath
$projectDir = Split-Path $SolutionPath -Parent

$msbuild = Find-MSBuild
Build-Project $msbuild $SolutionPath "Win32"
Build-Project $msbuild $SolutionPath "x64"

$x32 = Get-Shellcode (Join-Path $projectDir "Release\inject-shellcode.exe")
$x64 = Get-Shellcode (Join-Path $projectDir "x64\Release\inject-shellcode.exe")

# Update main.cpp
Write-Host "Updating main.cpp..." -ForegroundColor Yellow
$content = Get-Content $MainCppPath -Raw

$content = [regex]::Replace($content, '(?s)(x32Shellcode\[\] =\s*)(?:"[^"]*"\s*)+;', 
    "`${1}$(Format-Bytes $x32)")

$content = [regex]::Replace($content, '(?s)(x64Shellcode\[\] =\s*)PRE_X64SHELLCODE_VIRTUAL_FREE(?:\s*"[^"]*")+;', 
    "`${1}PRE_X64SHELLCODE_VIRTUAL_FREE`r`n$(Format-Bytes $x64)")

Set-Content $MainCppPath $content -NoNewline

Write-Host "Done! x32: $($x32.Length), x64: $($x64.Length) bytes" -ForegroundColor Green
