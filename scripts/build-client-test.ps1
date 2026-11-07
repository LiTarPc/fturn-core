param(
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9.+-]+$')]
    [string]$Version = '4.2.4-test.1',
    [string]$GoExe = 'go',
    [switch]$SkipAndroid
)
$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $sourceRoot "dist/test-client-$Version"
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$toolsRoot = Join-Path $outputRoot 'tools'
New-Item -ItemType Directory -Force -Path $toolsRoot | Out-Null
$saved = @{}
foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN','GOROOT','PATH','ANDROID_NDK_HOME')) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
function Invoke-Go([string[]]$GoArguments) {
    & $GoExe @GoArguments
    if ($LASTEXITCODE -ne 0) { throw "Go failed: $($GoArguments -join ' ')" }
}
Push-Location $sourceRoot
try {
    $env:GOTOOLCHAIN = 'auto'
    $toolchainRoot = (& $GoExe env GOROOT).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve Go toolchain' }
    $env:GOROOT = $toolchainRoot
    $env:PATH = "$toolsRoot;$toolchainRoot/bin;$env:PATH"
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $linkFlags = "-s -w -checklinkname=0 -X main.version=$Version"
    Invoke-Go -GoArguments @('build','-trimpath','-ldflags',$linkFlags,'-o',"$outputRoot/client-windows-amd64.exe",'./cmd/client')
    & "$outputRoot/client-windows-amd64.exe" -version
    if ($LASTEXITCODE -ne 0) { throw 'Windows version smoke test failed' }
    if (-not $SkipAndroid) {
        $env:GOOS = 'android'
        $env:GOARCH = 'arm64'
        Invoke-Go -GoArguments @('build','-trimpath','-ldflags',$linkFlags,'-o',"$outputRoot/client-android-arm64",'./cmd/client')
        $env:GOOS = 'windows'
        $env:GOARCH = 'amd64'
        Invoke-Go -GoArguments @('build','-o',"$toolsRoot/gomobile.exe",'golang.org/x/mobile/cmd/gomobile')
        Invoke-Go -GoArguments @('build','-o',"$toolsRoot/gobind.exe",'golang.org/x/mobile/cmd/gobind')
        if (-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath "$env:JAVA_HOME/bin/javac.exe")) { throw 'JAVA_HOME must point to a JDK' }
        if (-not $env:ANDROID_HOME) { throw 'ANDROID_HOME must point to the Android SDK' }
        if (-not $env:ANDROID_NDK_HOME) {
            $ndkRoot = Join-Path $env:ANDROID_HOME 'ndk/28.2.13676358'
            if (-not (Test-Path -LiteralPath $ndkRoot)) { throw 'Set ANDROID_NDK_HOME to an installed NDK' }
            $env:ANDROID_NDK_HOME = $ndkRoot
        }
        $env:PATH = "$toolsRoot;$toolchainRoot/bin;$env:JAVA_HOME/bin;$env:PATH"
        $env:CGO_ENABLED = '1'
        & "$toolsRoot/gomobile.exe" bind -target 'android/arm64,android/arm' -androidapi 24 -javapkg 'com.freeturn.core' -trimpath -ldflags "-s -w -checklinkname=0 -X github.com/LiTarPc/fturn-core/mobile.version=$Version" -o "$outputRoot/freeturn-$Version.aar" ./mobile
        if ($LASTEXITCODE -ne 0) { throw 'Android AAR build failed' }
    }
    Write-Output "Client test cores: $outputRoot"
}
finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    Pop-Location
}
