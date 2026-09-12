# Status da Implementação - Linux Game no LiteBox Windows Userland

**Supervisão**: Codex
**Data**: 11/09/2026
**Escopo delimitado**: Apenas `examples/linux_game/` e artefatos em `target/linux-game/`.

---

## 1. Escopo e Limitações do Ambiente
O LiteBox no Windows Userland é um ambiente de isolamento em desenvolvimento. Não há suporte a subsistemas como rede IP (`unimplemented`), nem pilha gráfica de desktop Linux (X11, Wayland, SDL2) ou drivers de áudio de kernel (ALSA, PulseAudio, PipeWire). Por essa razão, este projeto consiste em uma **demonstração técnica adaptada**, onde:
- A lógica física, simulação matemática, renderização do framebuffer RGB e síntese digital PCM ocorrem exclusivamente dentro do processo convidado Linux em espaço de usuário (`main.c`).
- O transporte de entrada/saída utiliza stdio binário multiplexado (`TICK`, `KEYP`, `KEYR`, `FRAM`, `SND0`).
- O host Windows (`host.py`) atua como camada de apresentação fina em Tkinter e WinMM.

---

## 2. Melhorias e Correções Realizadas

1. **Taxa de Quadros Precisa (~30 FPS)**:
   - Uso de `time.perf_counter()` com prazos absolutos de frame (`FRAME_INTERVAL = 1.0 / 30.0`), desacoplando o agendamento do tempo de renderização e evitando drift cumulativo de timers.

2. **Backend de Áudio WinMM (`winmm.dll`) Rigoroso**:
   - Declaração explícita de `argtypes` e `restype` para todas as funções (`waveOutOpen`, `waveOutPrepareHeader`, `waveOutWrite`, `waveOutReset`, `waveOutUnprepareHeader`, `waveOutClose`).
   - Todos os retornos `MMRESULT` são avaliados.
   - Contabilidade precisa: apenas buffers com flag `WHDR_DONE` antes do reset são considerados concluídos/reproduzidos. Buffers cancelados durante reset ou descarte são registrados separadamente.
   - Verificação de amostras de PCM não silenciosas submetidas.

3. **Validação de Entrada sem Perda de Teclas**:
   - Comparação atômica entre estado desejado (`desired_keys`) e enviado (`sent_keys`), eliminando o risco de perder eventos de liberação (`KEYR`) decorrentes de filas cheias ou sobreposições rápidas.
   - Liberação de todas as teclas em perda de foco (`<FocusOut>`).

4. **Visibilidade da GUI**:
   - O host invoca `root.deiconify()`, `root.lift()` e foco inicial para garantir que a janela apareça no primeiro plano, sem travá-la como topmost permanentemente.

5. **Tratamento Estrito de Erros e EOF**:
   - Leitura de protocolos com `read_exact`. Qualquer EOF inesperado ou pacote malformado encerra a sessão com erro e aborta testes automatizados.

6. **Proteção contra Deadlocks nos Testes**:
   - Todas as instâncias executadas em `test_headless.py` (inclusive helpers de medição de ticks) possuem watchdogs com encerramento forçado e wait do processo filho.

7. **Manifesto e Rastreabilidade (`build.py`)**:
   - `target/linux-game/manifest.json` registra hashes SHA256 de `main.c`, `host.py`, `build.py`, dos binários gerados, do TAR (`0755` USTAR), do runner compilado e inclui o estado de diff/patch do runtime.

8. **Launcher Simples (`launch.ps1`)**:
   - Script PowerShell autônomo que resolve caminhos, constrói dependências faltantes e executa o jogo sem necessidade de privilégios de administrador.

---

## 3. Evidências Reais de Teste

### A. Teste Headless Completo (`python examples/linux_game/test_headless.py`)
```
==================================================
  LiteBox Linux Game Headless End-to-End Test
==================================================
[*] Testing user input: comparing paddle pixel positions at identical tick count (tick 10)...
[PASS] Paddle position at tick 10: Left=49.5px < Neutral=79.5px < Right=109.5px
[*] Spawning LiteBox runner: <repo>\target\release\litebox_runner_linux_on_windows_userland.exe --initial-files <repo>\target\linux-game\game.tar /bin/breakout
[PASS] Received initial frame: 160x120 (57600 bytes)
[PASS] Received initial audio: 735 samples (1470 bytes)
[*] Simulating 15 game ticks to verify ball movement...
[PASS] Physics verified: Frame 15 has 54 differing color bytes from initial frame.
[*] Running game loop until dynamic non-silent collision audio is generated...
[PASS] Collision sound detected at tick 11: peak PCM amplitude = 12000
[PASS] Audio synthesis verified: Guest produced genuine synthesized waveforms.
[PASS] Graceful exit verified (return code 0).
==================================================
  ALL HEADLESS VERIFICATION CHECKS PASSED (100%)
==================================================
```

### B. Smoke Test GUI de 5 Segundos (`python examples/linux_game/host.py --smoke-seconds 5`)
```
=== SMOKE TEST METRICS ===
Rendered frames: 147
FPS: 29.3
Audio backend opened: True
Audio buffers submitted: 148
Audio buffers completed (playback finished): 146
Audio buffers canceled/discarded: 2
Non-silent audio chunks submitted: 13
Guest exit code: 0
Errors encountered: 0
Note: Audio playback was submitted via winmm waveOut API; audible output depends on hardware host speakers.
==========================

[SMOKE TEST PASSED] All GUI, frame rate, audio and guest criteria met.
```
