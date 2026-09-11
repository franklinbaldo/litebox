# Backend SDL2 e compatibilidade desktop

Planejamento revisado pelo supervisor em 2026-09-11 a partir da instância AGY
`plan/sdl-desktop`. Backend ainda não implementado; demo Breakout usa protocolo
próprio. Os jogos selecionados estão em [game-corpus.md](game-corpus.md).

## Decisão

Adicionar drivers de vídeo/entrada e áudio à SDL2 upstream, compilada como ELF
Linux `libSDL2-2.0.so.0`. Manter seu core, renderizador software, conversões de
pixels, mixer de formatos e APIs públicas. Uma reimplementação parcial de símbolos
SDL não é a estratégia escolhida: aplicações usam mais APIs e semânticas do que
uma lista inicial de chamadas consegue cobrir.

Primeiro perfil: x86_64 + musl, jogos recompilados do código upstream sem patches
na lógica, com bibliotecas e assets fixados. Depois, perfil glibc e executáveis
Linux pré-compilados sem recompilação. Passar no primeiro perfil não prova o
segundo. Bibliotecas Windows DLL não satisfazem dependências ELF do guest.

Antes de implementar o driver, verificar carregamento do interpretador ELF,
DT_NEEDED, TLS, relocations e reescrita de syscalls nas bibliotecas dinâmicas.
Testar threads/clone, futex, clocks, sinais e poll no runner Windows. Encontrar
uma implementação no shim não equivale a validar essa combinação de runtime.

## Integração SDL

Fixar uma versão/commit SDL2 antes do primeiro patch. Pontos de integração atuais:

| Área | Operações internas a conectar |
|---|---|
| Vídeo | bootstrap do driver, VideoInit/VideoQuit, CreateSDLWindow, DestroyWindow, título/tamanho, CreateWindowFramebuffer, UpdateWindowFramebuffer, DestroyWindowFramebuffer |
| Entrada | PumpEvents, espera com timeout/wakeup; enviar teclado, texto, mouse relativo/absoluto, botões, foco e fechamento ao core SDL |
| Áudio | bootstrap SDL_AudioDriverImpl: abrir/fechar dispositivo, obter buffer, esperar espaço e entregar PCM; reutilizar thread/callback e conversão do core SDL |

Referências oficiais:
[SDL_VideoDevice](https://github.com/libsdl-org/SDL/blob/SDL2/src/video/SDL_sysvideo.h),
[driver dummy](https://github.com/libsdl-org/SDL/blob/SDL2/src/video/dummy/SDL_nullvideo.c),
[SDL_AudioDriverImpl](https://github.com/libsdl-org/SDL/blob/SDL2/src/audio/SDL_sysaudio.h).
Os nomes internos devem ser conferidos novamente no commit fixado.

Chocolate Doom permite `force_software_renderer` em sua configuração. Começar
por ele com SDL2_mixer habilitado e Freedoom: desabilitar som não passa no teste.
Sopwith solicita PRESENTVSYNC e render targets; testar a SDL escolhida com essas
flags antes de promovê-lo. Se o caminho software existente não satisfizer a
semântica, implementar a extensão genérica necessária e medir pacing. Não
anunciar aceleração ou sincronização que o driver não entrega.

C-Dogs 2.4.0 solicita ACCELERATED e TARGETTEXTURE sem fallback nesse ponto:
segunda etapa, dependente de renderizador adequado. Neverball exige contexto e
chamadas OpenGL: etapa posterior, com desenho separado da ponte gráfica. Render
software da lógica Doom não exige a mesma infraestrutura de um cliente OpenGL.

## Transporte proposto desktop_fd_v1

O guest recebe FD(s) dedicados realmente instalados na tabela do shim, ou abre
um dispositivo virtual explicitamente implementado. Variáveis de ambiente com
números de FD e handles Win32 sozinhos não criam essa conexão. stdout/stderr ficam
disponíveis ao jogo. O caminho deve ligar devices/FDs do LiteBox ao provider
Windows, com semântica de read/write/poll/close e cancelamento por EOF.

Usar pipes host inicialmente. Memória compartilhada fica condicionada a medidas
de cópias/CPU/latência e a um contrato explícito de mapeamento no guest.

Rascunho de framing: cabeçalho de **12 bytes**, campos little-endian separados,
`magic[4] = LBG1`, `type:u16`, `stream:u16`, `payload_length:u32`. Nunca serializar
struct com padding. A versão final precisa de tabela de mensagens e vetores de
teste antes dos dois lados serem implementados. HELLO/ACK negocia versão, formatos,
dimensões, tamanho máximo de payload, filas e recursos obrigatórios; rejeitar
incompatibilidade antes de abrir a sessão.

Limites iniciais propostos: uma janela, 1280x720, BGRA8 com ordem de bytes definida,
até dois frames pendentes; áudio S16LE mono/estéreo em 22050/44100/48000 Hz. Cada
frame carrega sequência, dimensões, pitch e tamanho verificado com aritmética
checada. O parser valida limites antes de alocar. Estes limites são configuráveis
na negociação, não valores silenciosamente impostos a jogos incompatíveis.

Filas de áudio/controle separadas da fila de frames evitam que um frame grande
retenha áudio e fechamento. Threads produtoras não intercalam mensagens no mesmo
pipe. O dispatcher continua drenando entrada/áudio enquanto apresentação aguarda
créditos; read/write parciais, EINTR, EOF e bloqueio têm testes próprios.

Áudio usa relógio de amostras efetivamente consumidas pelo host, independente de
FPS. Reportar frames de áudio reproduzidos, ocupação, underruns e formato obtido.
Fila inicial de 40–80 ms para medição, com limite máximo explícito; callback não
espera pelo renderizador. Medir e reduzir latência sem acumular atraso de som.
Perda de foco libera teclas e captura de mouse. Fechamento gera SDL_QUIT e encerra
threads/canais; timeout cancela sessão sem deixar processo órfão.

## Persistência e evolução além de SDL

O TAR em memória atual não preserva saves entre processos. Implementar backend
persistente por jogo, HOME/XDG e operações de arquivo usadas pelos candidatos,
incluindo criação, rename, stat, flush e recuperação após falha. Exportação só
no encerramento não atende ao requisito de crash. Contrato compartilhado com o
[instalador](windows-install-plan.md).

SDL2 é uma primeira família de compatibilidade. Jogos SDL3 precisam de outro
backend. Clientes X11 e Wayland usam protocolos de display; bibliotecas ALSA,
PulseAudio e PipeWire usam outros caminhos de áudio. Após os jogos SDL2 passarem,
inventariar binários reais e escolher a próxima família por cobertura. Avaliar
servidor X11/compositor Wayland e serviço de áudio existentes antes de reimplementar
protocolos. Nunca contar um jogo rodando pelo driver SDL customizado como teste
de X11/Wayland/ALSA. OpenGL/Vulkan também requerem contratos próprios.

## Sequência de implementação

| PR | Dono e caminhos propostos | Dependência e gate |
|---|---|---|
| S1: ABI e transporte guest | AGY runtime: litebox/src/fs/devices.rs, litebox_shim_linux/, litebox_platform_windows_userland/, runner Windows e seus testes | ELF dinâmico+thread e canal real read/write/poll/EOF; bytes fragmentados e limites inválidos |
| S2: host nativo e drivers SDL | AGY runtime: novo litebox_sdl/, novo tools/litebox_desktop_host/ | S1; janela, textura atualizada, teclado/mouse, PCM audível; sem dependência Python final |
| S3: persistência | AGY runtime: filesystem/provider e testes do runner | S1; save, encerrar, reiniciar e recuperar; falha durante rename/flush |
| S4: jogos e medição | AGY corpus: packages/games/, testes e docs/desktop/ | S2/S3; Chocolate+Freedoom e Sopwith, sessão de 10 min, saves e áudio |
| S5: produto instalado | AGY instalação: tools/litebox_launcher/, packages/games/ | S4 e I2/I3; menu Iniciar, atualização/rollback e saves preservados |

Paths novos são propostas, não afirmação de que os módulos já existem. O mesmo
dono faz alterações de shim/provider para evitar colisões. Instalador e corpus
podem avançar em manifestos, build recipes e testes enquanto S1 está em andamento.

Parar e corrigir o marco se houver dependência ELF não resolvida, canal inacessível,
deadlock em áudio/entrada, corrupção de save ou necessidade de patch específico
na lógica do jogo. Mudanças necessárias nas interfaces de Platform são revisadas
pelo supervisor; não estão proibidas se forem o caminho correto.
