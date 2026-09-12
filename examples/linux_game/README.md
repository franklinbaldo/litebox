# Breakout Linux no LiteBox (Windows Userland)

Demonstração técnica adaptada de um executável Linux estático (**Breakout**) rodando dentro do isolamento do **LiteBox** no Windows Userland.

> **Nota sobre escopo e limitações do ambiente**:
> Esta implementação é uma **demonstração técnica adaptada** baseada no transporte bidirecional determinístico multiplexado via stdio (`stdin`/`stdout`). O LiteBox no Windows Userland atualmente possui subsistemas como rede IP (`unimplemented`) e servidores gráficos/áudio padrão do ecossistema Linux (como X11, Wayland, SDL2 ou ALSA) ainda não expostos ou não emulados na camada userland. Desta forma, a demo executa um guest estático com lógica e síntese próprias, comunicando os frames e buffers PCM diretamente com o host Windows.

---

## Arquitetura e Protocolo

1. **Guest ELF Linux (`main.c`)**:
   - Compilado via Zig cc para `x86_64-linux-musl` estático (`-static -O2`).
   - Reescrito via `litebox_syscall_rewriter.exe` para interceptação de chamadas de sistema.
   - Toda a física do jogo, matriz de tijolos, lógica de pontuação, renderização de framebuffer RGB24 (160x120) e síntese digital de som PCM mono (22.050 Hz, 735 amostras por tick) rodam no processo Linux.
   - Comunicação via streams padrão binários.

2. **Protocolo Stdio**:
   - **Guest -> Host (stdout)**:
     - `FRAM` (8 bytes cabeçalho: `'F','R','A','M'`, u16 largura=160, u16 altura=120 + 57.600 bytes RGB24).
     - `SND0` (6 bytes cabeçalho: `'S','N','D','0'`, u16 amostras=735 + 1.470 bytes PCM 16-bit mono).
   - **Host -> Guest (stdin)**:
     - `TICK` (4 bytes): avança 1 ciclo de simulação a ~30 FPS.
     - `KEYP` + byte (1=Esquerda, 2=Direita, 3=Espaço, 27=Esc): pressionamento de tecla.
     - `KEYR` + byte: liberação de tecla.

3. **Host Windows (`host.py`)**:
   - Escrito em Python 3 usando apenas a biblioteca padrão (`tkinter` e `ctypes`).
   - Agendamento de ticks com `time.perf_counter()` e prazos absolutos para manter taxa constante de ~30 FPS.
   - Renderização gráfica com `tk.PhotoImage(data=ppm, format="PPM")` e escala nítida (480x360).
   - Elevação de janela via `root.deiconify()`, `root.lift()` e foco inicial sem manter travamento permanente no topo.
   - Áudio de baixa latência usando WinMM `waveOut` com tipagem e checagem de erros estritas (`MMRESULT`, `WAVEFORMATEX`, `WAVEHDR`). Buffers cancelados por reset não são contabilizados como reproduzidos.
   - Sincronização de teclado baseada em snapshot de estado desejado versus enviado, eliminando perda de key-up.
   - Drenagem contínua de stderr em thread dedicada.
   - Suporte a `--smoke-seconds N` com métricas detalhadas e validação estrita de sucesso.

---

## Como Construir e Executar

### 1. Início Rápido (Launcher Automático)
Execute no PowerShell (sem necessidade de privilégios de administrador):
```powershell
powershell -ExecutionPolicy Bypass -File examples/linux_game/launch.ps1
```
O script resolve caminhos automaticamente, verifica/compila os binários caso ausentes e inicia o jogo.

### 2. Compilação e Empacotamento Manual
```powershell
python examples/linux_game/build.py
```
Gera:
- `target/linux-game/breakout.elf`
- `target/linux-game/breakout.hooked`
- `target/linux-game/game.tar` (modo explícito `0755`, formato USTAR)
- `target/linux-game/manifest.json` (hashes SHA256 de fontes, binários, TAR, runner e diff do patch de stdout flush do runtime)

### 3. Teste Automatizado Headless
```powershell
python examples/linux_game/test_headless.py
```
Valida de ponta a ponta sem GUI:
- Inicialização do executável pelo runner LiteBox.
- Verificação de dimensões FRAM (160x120) e contagem de amostras SND0 (735).
- Deslocamento de pixels da raquete no mesmo tick com e sem entrada (`Left` < `Neutral` < `Right`).
- Síntese real de som dinâmico em eventos de colisão.
- Timeouts por instância com término forçado em caso de falha.

### 4. Teste de Fumaça GUI (Smoke Test de 5 segundos)
```powershell
python examples/linux_game/host.py --smoke-seconds 5
```
Abre a interface gráfica real, reproduz o áudio, e encerra após 5 segundos reportando métricas completas de FPS, buffers e integridade do processo guest.

### 5. Controles
- `A` ou `Seta Esquerda`: mover a raquete para a esquerda
- `D` ou `Seta Direita`: mover a raquete para a direita
- `Espaço`: reiniciar o jogo
- `Esc`: sair
