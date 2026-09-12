# Jogos existentes para testes

Seleção de 2026-09-11, pesquisada pela instância AGY `plan/game-corpus` e revisada
pelo supervisor. **Todos os jogos abaixo ainda não foram executados no LiteBox.**
Breakout adaptado permanece como controle já validado pelo usuário, separado deste
corpus de terceiros.

| Ordem | Jogo fixado | O que queremos testar |
|---|---|---|
| 1 | [Chocolate Doom 3.1.1](https://github.com/chocolate-doom/chocolate-doom/tree/chocolate-doom-3.1.1) + [Freedoom 0.13.0](https://github.com/freedoom/freedoom/tree/v0.13.0) | imagem por software, mouse relativo/teclado, efeitos e música, save/load |
| 2 | [SDL Sopwith 2.9.0](https://github.com/fragglet/sdl-sopwith/tree/sdl-sopwith-2.9.0) | jogo pequeno 2D, teclado, síntese de PC speaker, escala e recordes |
| 3 | [C-Dogs SDL 2.4.0](https://github.com/cxong/cdogs-sdl/tree/2.4.0) | renderer acelerado, texturas de destino, mixer, campanhas e configurações |
| 4 | [Neverball 1.6.0](https://github.com/Neverball/neverball/tree/neverball-1.6.0) | contexto/chamadas OpenGL, entrada contínua, áudio e desempenho 3D |

Freedoom é o conjunto de dados do primeiro jogo da tabela, não outro executável.
Usar inicialmente Phase 1 com uma sequência fixa de níveis; não distribuir WADs
proprietários do Doom. Neverball entra depois do marco de OpenGL. SDL3 Snake pode
ser uma fixture futura, mas não integra esta bateria SDL2 nem substitui teste de som.

## Por que esta ordem

Chocolate Doom tem `force_software_renderer` e fallback explícito em
[i_video.c](https://github.com/chocolate-doom/chocolate-doom/blob/chocolate-doom-3.1.1/src/i_video.c).
Isso reduz uma incerteza inicial. Manter SDL2_mixer habilitado: uma build sem som
não atende ao pedido. A documentação de
[Freedoom 0.13.0](https://github.com/freedoom/freedoom/blob/v0.13.0/README.adoc)
orienta compatibilidade vanilla e teste de níveis no Chocolate Doom; ainda assim,
estabelecer referência nativa Linux para os níveis escolhidos antes de comparar.

Sopwith tem poucas dependências e áudio sintetizado via SDL_OpenAudioDevice, mas
[video.c](https://github.com/fragglet/sdl-sopwith/blob/sdl-sopwith-2.9.0/src/sdl/video.c)
solicita PRESENTVSYNC e usa render targets. Não presumir que qualquer driver de
framebuffer satisfaz essas operações. Validar também SDL_GetPrefPath e o diretório
de high scores configurado na build.

C-Dogs exige ACCELERATED e TARGETTEXTURE em
[window_context.c](https://github.com/cxong/cdogs-sdl/blob/2.4.0/src/cdogs/window_context.c),
sem retry software nesse trecho. Serve como teste esperado de incompatibilidade
no primeiro marco e como teste positivo quando houver renderizador adequado.
Neverball depende de SDL2 e OpenGL no
[Makefile](https://github.com/Neverball/neverball/blob/neverball-1.6.0/Makefile).
Sua pilha gráfica será um marco separado.

## Reprodutibilidade e licenças

[game-corpus.json](game-corpus.json) fixa tags e commits completos. Os quatro
commits de código foram conferidos nos checkouts dos projetos oficiais; o commit
Freedoom foi conferido pela API do GitHub. Hash de código não substitui hash dos
artefatos finais: `artifact_sha256` permanece null até produzir/verificar pacotes.

Chocolate Doom e Sopwith têm avisos GPL; Freedoom tem licença própria em
[COPYING.adoc](https://github.com/freedoom/freedoom/blob/v0.13.0/COPYING.adoc).
C-Dogs documenta GPL/BSD para código e diferentes licenças de dados no
[README](https://github.com/cxong/cdogs-sdl/blob/2.4.0/README.md).
Neverball mantém avisos gerais e por componente. Antes de empacotar, inventariar
arquivos de dados, música, fontes e ícones com avisos e versões de licença. A
licença do código não é evidência suficiente para todos os assets. Pacotes ainda
não estão aprovados para distribuição; o inventário é parte da tarefa do corpus.

## Aceitação de cada jogo

1. Construir código upstream sem alteração na lógica do jogo; registrar flags,
   libc, bibliotecas, assets, commit e hashes. Mudanças de empacotamento são explícitas.
2. Abrir janela, iniciar partida e jogar por 10 minutos; teclado/mouse, foco,
   pausa e fechamento funcionam sem processos órfãos.
3. Ouvir efeitos e música quando houver. Registrar formato, latência, ocupação da
   fila e underruns; inicializar SDL áudio com sucesso sozinho não basta.
4. Salvar, terminar o processo, iniciar outro e recarregar. Configurações e recordes
   persistem quando o jogo os oferece.
5. Instalar em conta Windows sem ferramentas de desenvolvimento, localizar no
   Iniciar, abrir pelo atalho e reconhecer ícone/agrupamento da janela.
6. Atualizar/reverter binários e desinstalar/reinstalar preservando saves.

Registrar FPS e tempos de frame p50/p95/p99, CPU host+runner, memória e tempo de
abertura no mesmo computador, resolução e roteiro. Comparar com execução Linux
nativa da mesma build. Proposta inicial: p95 dentro de dois intervalos de frame
do alvo do jogo, sem crescimento contínuo de memória/fila de áudio e sem cortes
audíveis em 10 minutos. Orçamento numérico de CPU/latência será fechado após a
primeira medição; não atribuir um número universal a jogos distintos.

O relatório distingue: não iniciado, bloqueado por ABI/syscall, sem vídeo, sem
som, jogável, persistência validada e instalação validada. Marcar simplesmente
“funciona” só depois de todos os critérios aplicáveis.
