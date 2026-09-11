# Validação do supervisor — 11/09/2026

Implementação produzida com o `agy` via CLI, orientada e revisada pelo Codex.
Objetivo: um jogo Linux pequeno com janela, controles e som no Windows.

## Base e correção do runtime

- Fork: `franklinbaldo/litebox`.
- Base original: `7af6242f0729c1f0224161c7cec0afc114994cf6`.
- Upstream Microsoft incorporado por fast-forward na branch local:
  `f3f3e2f964242d3937c63b71e595ef64b2939f23` (33 commits).
- Entre as atualizações úteis estão as correções de passagem de argumentos
  para exceções Windows (`831b3018`) e de interrupções na entrada do guest
  (`8b0406a4`).
- Correção local adicional: descarregar o stdout após cada escrita do guest.
  O buffering por linha do Rust retinha pacotes binários enquanto o guest
  esperava entrada. O teste novo `binary_stdout_is_visible_before_next_input`
  exige receber um pacote sem newline antes de enviar a resposta ao processo.

## Evidências verificadas

- `cargo test --locked --release -p litebox_runner_linux_on_windows_userland`:
  quatro testes passaram, incluindo os dois loaders oficiais e o teste de
  comunicação binária com seu processo auxiliar.
- `cargo clippy --locked --release --all-targets --all-features -p
  litebox_runner_linux_on_windows_userland -- -D warnings`: passou.
- `cargo fmt --all -- --check` e `git diff --check`: passaram.
- Teste headless: raquete no tick 10 em **49,5 / 79,5 / 109,5 pixels** para
  esquerda / neutro / direita; áudio de colisão com pico PCM **12000**;
  encerramento do executável Linux com código 0.
- Validação independente da janela por 5 segundos: **149 quadros, 29,61 FPS**,
  **150 buffers de áudio submetidos, 147 concluídos e 3 cancelados ao fechar**;
  15 buffers não silenciosos; saída 0; nenhum erro reportado.
- Imagem da janela inspecionada em `target/linux-game/gui-supervisor.png`.
- Manifesto local em `target/linux-game/manifest.json`, com hashes de fontes,
  binários e patch do runtime.
- Amostra de 38 segundos com a janela aberta: host Python e runner juntos
  usaram **46,1 MiB de memória residente** e CPU equivalente a **17,5% de um
  núcleo** em média. Registro em `target/linux-game/performance.json`.

Os contadores de áudio comprovam geração de PCM no guest e reprodução aceita
e concluída pelo dispositivo WinMM. A tentativa adicional de captura por
loopback WASAPI falhou com `invalid argument` neste dispositivo; não serve
como confirmação acústica. Com a janela aberta, o usuário confirmou:
**“Imagem, controles e som funcionando”**. A validação funcional foi concluída.

## Limite do resultado

Este Breakout é um ELF Linux adaptado para transportar pixels, entrada e PCM
por stdio. A lógica, a renderização e a síntese de som rodam no LiteBox; Python
apresenta os pixels e envia o PCM ao dispositivo Windows. O resultado não
estabelece compatibilidade geral com jogos SDL/X11/Wayland/ALSA sem adaptação.

Os arquivos novos não atribuem seu copyright à Microsoft. Os avisos originais
dos arquivos upstream foram preservados.
