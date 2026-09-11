# Instalação de jogos no Windows

Proposta revisada pelo supervisor em 2026-09-11 a partir da instância AGY
`plan/windows-install`. Não há instalador implementado nesta entrega.

## Experiência desejada

O usuário instala um pacote, encontra o nome e o ícone do jogo em Todas as
aplicações no menu Iniciar, joga e mantém seus saves ao atualizar ou reinstalar.
O produto distribui launcher, host gráfico e runner nativos pré-compilados;
Rust, Python, Git e compiladores não são dependências do usuário final.
Converter o host Python da demo para um host nativo é uma tarefa explícita.

Escolhemos inicialmente um instalador EXE por usuário pela flexibilidade para
registrar jogos independentes e compartilhar versões do runtime. MSIX pode ser
avaliado depois para distribuição do launcher/runtime: exige uma estratégia de
identidade, assinatura e atualização; não é considerado tecnicamente impossível.

## Layout e identidade

Resolver diretórios pelas Known Folders, sem presumir nomes traduzidos ou unidade C:.

```text
LocalAppData/LiteBox/bin/LiteBox.exe              launcher estável
LocalAppData/LiteBox/runtimes/<runtime-id>/       versões imutáveis
LocalAppData/LiteBox/packages/<game-id>/<version>-<revision>/
LocalAppData/LiteBox/state/<game-id>.json        versão ativa e runtime exato
LocalAppData/LiteBox/icons/<game-id>.ico         ícone estável
LocalAppData/LiteBox/data/<game-id>/             saves e configurações
LocalAppData/LiteBox/transactions/<transaction-id>.json
Programs/LiteBox/<nome-do-jogo>.lnk
```

O atalho usa `IShellLinkW`, destino `LiteBox.exe` e argumentos `launch <game-id>`.
O launcher resolve o estado e fixa os caminhos exatos de pacote/runtime durante
toda a sessão. O manifesto fornece argv como lista; não há execução via shell
nem hooks de instalação arbitrários. O launcher faz o quoting Windows correto.

`IPropertyStore` atribui `System.AppUserModel.ID` estável por jogo ao atalho.
O processo que efetivamente cria a janela aplica o mesmo ID antes de qualquer UI;
se houver IDs diferentes por janela, usar `SHGetPropertyStoreForWindow`.
`WM_SETICON` configura ícones, não substitui a atribuição do AppUserModelID.
O ID não inclui a versão do pacote. Ver
[AppUserModelIDs](https://learn.microsoft.com/en-us/windows/win32/shell/appids).

O destino é `FOLDERID_Programs` do usuário, documentado em
[Known Folders](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid).
A aceitação inclui aparecer em Todas as aplicações e ser encontrado pela busca;
a indexação pode demorar. Não se promete fixação automática no Iniciar ou na barra.

Registrar cada jogo em `HKCU/Software/Microsoft/Windows/CurrentVersion/Uninstall/`
com nome, versão, ícone, caminho e comando de desinstalação devidamente citado.
Usar caminhos absolutos resolvidos nos valores REG_SZ, não variáveis `%...%`.
Publisher/attribution identificam o empacotador e autores reais; a página do fork
é `https://github.com/franklinbaldo/litebox`. Novos arquivos não recebem copyright
Microsoft; avisos de código upstream e assets de terceiros são preservados.

## Pacotes, persistência e atualização

O [schema](game-package.schema.json) é um rascunho do contrato, não prova de que
seus recursos existem. O runtime deve rejeitar recursos indisponíveis. Validar
manifesto e hashes de todos os conteúdos; hashes demonstram integridade, não
autenticidade. A distribuição deve definir como confiar no catálogo/manifesto.
Além do schema, a implementação rejeita caminhos que escapem da raiz, links de
arquivo perigosos e arquivos fora dos limites de tamanho do perfil.

O runtime atual carrega um TAR em memória. Ainda falta implementar persistência
para os caminhos de save/config realmente usados pelos jogos. Mapear uma pasta
do Windows no desenho não implementa essa função. HOME/XDG e caminhos do guest
devem ser configurados sem patches específicos na lógica do jogo. O backend de
arquivos persistentes precisa delimitar a raiz por jogo e tratar rename/flush.
Exportar no encerramento só pode ser uma etapa experimental: sozinho não atende
ao critério de recuperar saves após crash. Saves não seguem rollback de binários;
mudanças incompatíveis de formato exigem backup/migração explícitos.

Protocolo de instalação/atualização:

1. Adquirir trava por pacote; gravar journal de intenção com IDs e etapas tipadas.
2. Preparar nova versão em staging, verificar conteúdo/licenças/recursos e mover
   para o diretório final imutável no mesmo volume.
3. Gravar e descarregar novo arquivo de estado. Publicá-lo por substituição de
   arquivo, com recuperação para estados ausente/antigo/novo. Não usar
   `ReplaceFileW` para substituir uma junção de diretório: essa API trata arquivos.
4. Criar/reparar ícone estável, atalho e registro de desinstalação de forma
   idempotente. Só marcar conclusão quando essas etapas forem verificadas.
5. Em reinício, reconciliar journal e estado instalado. Testar falha em cada etapa,
   inclusive arquivo de estado ausente e falha parcial de integração no Shell.

Consultar [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
para semântica e tratamento de erros da substituição do arquivo de estado.
A durabilidade após queda de energia deve ser medida, não presumida.

Sessões em execução mantêm sua versão e lease do runtime; novas sessões usam o
estado publicado. Limpeza só remove versões sem referências de pacotes, rollback
ou processos ativos. Serializar sessões que escrevem nos mesmos saves no MVP.
O bootstrap estável também exige atualização: preparar uma versão nova e aplicar
quando não estiver em uso, com helper pré-compilado e recuperação do estado.

Desinstalar remove atalhos, registro e conteúdo sem uso, preservando dados por
padrão. Se o jogo estiver aberto, adiar a remoção dos binários. Apagar saves exige
ação explícita do usuário. Reinstalar o mesmo ID recupera os dados preservados.

## Entregas e critérios

| Entrega | Responsável | Dependência | Aceitação |
|---|---|---|---|
| I1: pacote da demo e host nativo | AGY instalação | protocolo atual | abrir e ouvir Breakout sem Python instalado |
| I2: launcher, estado e Shell | AGY instalação | I1 | instalar sem admin, abrir por atalho, ícone/agrupamento corretos, desinstalar |
| I3: journal, atualização e dados | AGY instalação + runtime | backend de persistência | falhas injetadas por etapa, atualização com jogo aberto, saves após reinício |
| I4: primeiro jogo do corpus | AGY corpus | I2/I3 e backend SDL | instalar, jogar com som, salvar, atualizar, reabrir pelo Iniciar |

Pastas propostas: `tools/litebox_launcher/`, `packages/games/` e testes de integração
Windows. O dono do backend edita os crates do runtime; a instância de instalação
não faz mudanças concorrentes nesses crates. O supervisor integra contratos e
revisa testes em uma conta Windows sem ferramentas de desenvolvimento.

Parar a promoção para pacote suportado se faltar som, persistência, licença de
algum asset, recuperação de instalação ou se o jogo depender de patch na sua
lógica para conversar diretamente com o host. A demo continua sendo controle.
