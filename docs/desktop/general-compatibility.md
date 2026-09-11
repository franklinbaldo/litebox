# Compatibilidade compartilhada entre jogos

Diretriz do usuário em 2026-09-11: construir suporte abrangente a diferentes
tipos de jogos. A demo é um controle de regressão; seu protocolo fixo não é a
arquitetura final. Nenhum jogo novo deve ganhar um protocolo privado de frames,
áudio ou controles. Código novo de produto será Rust. Bibliotecas e jogos upstream
mantêm sua implementação e autoria.

## Fronteiras da implementação

Fluxo pretendido: jogo Linux → bibliotecas Linux → interfaces suportadas pelo
runtime LiteBox → transporte desktop → serviços nativos Windows. O instalador
seleciona uma versão do runtime e verifica requisitos; não implementa APIs gráficas.

| Camada compartilhada | Contrato necessário | Situação atual |
|---|---|---|
| ABI Linux | ELF, loader, libc, threads, futex, relógios, memória, arquivos e poll | Existem partes no LiteBox; falta medir cobertura por jogo |
| Transporte desktop | FD dedicado, handshake versionado, mensagens limitadas, fechamento e backpressure | Fundação `tools/litebox_desktop_transport`; integração com os FDs do guest ainda pendente |
| Janelas e entrada | Dimensões negociadas, resize, foco, teclado, texto, mouse absoluto/relativo e gamepad | Demo tem janela fixa e três teclas |
| Áudio | Dispositivo virtual, formatos negociados, filas limitadas, conversão, relógio e recuperação | Host da demo usa PCM mono fixo |
| SDL | Drivers de vídeo, áudio e entrada para a SDL upstream, preservando sua API | Backend não implementado; SDL2 e SDL3 são alvos distintos |
| X11 e Wayland | Servidores/protocolos e sockets usados pelas bibliotecas Linux | Não implementados; escolher um primeiro após medir dependências do corpus |
| Renderização 3D | Contextos GL/EGL, recursos, sincronização e apresentação | Não implementada; software pode validar correção, aceleração precisa de projeto e medições próprios |
| Arquivos persistentes | Diretórios guest associados a dados por jogo, sem perder saves ao atualizar | Diretório host reservado pelo instalador; ainda sem montagem persistente no guest |
| Instalação | Identidade, versões imutáveis, requisitos, hashes, atalhos e remoção isolada | Launcher Rust em implementação; múltiplas identidades, validação e testes locais |

Uma camada SDL atende jogos que usam SDL. Bibliotecas que abrem X11, Wayland,
ALSA ou outros dispositivos diretamente exigem esses contratos adicionais.
Suporte a OpenGL não implica Vulkan; executar software de 32 bits também exige
um perfil de ABI separado. Esses requisitos devem produzir diagnóstico explícito,
em vez de uma tentativa silenciosa com o backend errado.

## Ordem de trabalho e critérios de saída

1. **Fundação Linux e transporte:** probes ELF estático e dinâmico, FD bidirecional,
   mensagens fragmentadas, poll, EOF, processo encerrando, consumidor lento e limite
   de memória. O crate de framing Rust já cobre handshake, fragmentação, limites,
   EOF/truncamento e fila limitada; falta ligá-lo aos FDs reais do shim. O mesmo caminho precisa funcionar sem janela. Nada de dependência
   dos nomes ou regras de um jogo.
2. **Desktop 2D compartilhado:** dimensões e áudio negociados, teclado completo,
   mouse, foco e resize; implementar drivers SDL2 sobre esse contrato. Validar
   Chocolate Doom + Freedoom e Sopwith sem patches de lógica. Uma build recompilada
   com backend SDL compartilhado deve ser identificada como tal.
3. **Persistência e instalação integrada:** executar dois jogos instalados, atalhos
   separados, configuração e saves sobrevivendo ao encerramento e atualização,
   remoção de um sem afetar o outro. Preservar uma pasta Windows, por si só, não
   satisfaz o teste de save dentro do Linux.
4. **Renderização mais ampla:** cobrir operações SDL_Renderer exigidas pelo corpus
   e depois contextos OpenGL/EGL, validando C-Dogs e Neverball respectivamente.
   Um fallback por CPU pode servir à correção; FPS, CPU, memória e latência definem
   se o backend também é utilizável.
5. **Binários Linux distribuídos:** medir loader/glibc e dependências sem recompilar
   o jogo; implementar a primeira rota X11 ou Wayland com base nas dependências
   observadas. Testar áudio pela API realmente usada. Documentar exatamente versão,
   arquitetura, bibliotecas e extensões cobertas.

## Build externo

As receitas atuais compilam SDL e os probes externamente com Zig/musl.
Um compilador executando dentro do LiteBox não faz parte deste escopo.

Em cada etapa, manter uma matriz por **jogo × versão × ABI × biblioteca gráfica ×
backend × áudio × entrada × persistência**. Estados: não testado, bloqueado com
causa, aprovado funcionalmente e aprovado em desempenho. Um teste sintético ou
um único jogo não promove a camada inteira para compatível.

O corpus inicial já está fixado em [game-corpus.json](game-corpus.json): Chocolate
Doom/Freedoom, SDL Sopwith, C-Dogs SDL e Neverball. Ele cobre progressão de gráficos,
mas não é evidência de SDL3, Vulkan, jogos comerciais, DRM ou anti-cheat. Esses
casos precisam de corpus e critérios próprios antes de prometer suporte.

## Pacotes e runtimes

O contrato geral proposto continua em `game-package.schema.json`; não deve ser
confundido com o formato provisório `package.json` do launcher experimental.
O formato provisório agora aceita múltiplos IDs, nomes, arquivos e papéis de
artefatos, e requisitos de runtime. Apenas `demo_stdio_v1` tem adaptador executável;
outros perfis são recusados. Instalar dois controles testa isolamento de pacotes,
não compatibilidade com dois jogos diferentes.

Antes da distribuição, consolidar os formatos em um único contrato: runtime
imutável referenciado por identidade e digest, conteúdo guest separado, argumentos
e ambiente tipados, capacidades versionadas, fontes/licenças e montagens
persistentes. O catálogo de capacidades vem da implementação validada do runtime,
nunca de uma afirmação fornecida pelo próprio pacote. Hash detecta divergência;
autenticidade de distribuição exige uma política própria de confiança/assinatura.

Runtimes podem coexistir e ser compartilhados. Atualizar o launcher não deve
trocar o runtime de uma sessão ativa. Atalhos chamam `LiteBox launch <id>`; nomes
de jogos não podem aparecer em decisões de compatibilidade no código do launcher.
