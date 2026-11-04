$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

python -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

python -m PyInstaller `
    --clean `
    --noconfirm `
    --onefile `
    --windowed `
    --name NetworkMonitor `
    --distpath dist `
    --workpath build\pyinstaller `
    --specpath build `
    --collect-all reportlab `
    --collect-all winotify `
    --exclude-module plyer `
    network_monitor\__main__.py
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Output "Application created at $PSScriptRoot\dist\NetworkMonitor.exe"
