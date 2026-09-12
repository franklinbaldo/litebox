# Copyright (c) franklinbaldo.
# Licensed under the MIT license.

<#
.SYNOPSIS
    Script de inicialização do Breakout Linux no LiteBox Windows Userland.
    Resolve caminhos relativos automaticamente, compila artefatos caso ausentes e inicia o jogo sem privilégios de administrador.
#>

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path "$ScriptDir\..\.."
$TargetDir = "$RepoRoot\target\linux-game"
$TarFile = "$TargetDir\game.tar"
$RunnerBin = "$RepoRoot\target\release\litebox_runner_linux_on_windows_userland.exe"
$RewriterBin = "$RepoRoot\target\release\litebox_syscall_rewriter.exe"

Write-Host "=== LiteBox Linux Breakout Launcher ===" -ForegroundColor Cyan
Write-Host "Diretório do script: $ScriptDir"
Write-Host "Raiz do repositório: $RepoRoot"

# Verificar binários do runner e rewriter
if (-not (Test-Path $RunnerBin) -or -not (Test-Path $RewriterBin)) {
    Write-Host "[*] Compilando binários do LiteBox release..." -ForegroundColor Yellow
    Push-Location $RepoRoot
    try {
        cargo build --locked --release -p litebox_syscall_rewriter -p litebox_runner_linux_on_windows_userland
        if ($LASTEXITCODE -ne 0) { throw "Falha ao compilar o runner LiteBox" }
    } finally {
        Pop-Location
    }
}

# Verificar se o jogo foi compilado e empacotado
if (-not (Test-Path $TarFile)) {
    Write-Host "[*] Artefatos do jogo ausentes. Executando build.py..." -ForegroundColor Yellow
    python "$ScriptDir\build.py"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Falha ao compilar o jogo via build.py"
    }
}

Write-Host "[+] Iniciando host gráfico..." -ForegroundColor Green
python "$ScriptDir\host.py" @args
exit $LASTEXITCODE
