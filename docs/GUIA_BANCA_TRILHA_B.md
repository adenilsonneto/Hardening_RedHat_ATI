# Guia da Trilha B: Identidade e Privilégio (Dores 5 e 6 da ATI)
## Documento de Apoio Didático, Técnico e Preparação para Banca
**Autor:** Aluno B (Graduação)  
**Projeto:** Hardening RedHat ATI (RHEL 9)  
**Data:** Novembro de 2026  

---

## 1. Visão Geral do Projeto

O projeto **Hardening RedHat ATI** é uma ferramenta de linha de comando desenvolvida em Python 3.9 para auditar, aplicar e reverter configurações de segurança no RHEL 9, combatendo riscos corporativos como movimentação lateral e abuso de privilégios (dores 5 e 6 da ATI). 

Uma **primitiva** é a menor unidade de código reutilizável encarregada de inspecionar e alterar um tipo específico de recurso do sistema (ex.: arquivos chave-valor, permissões ou regras de sudo). O projeto adota a **separação entre política e mecanismo**: as regras em YAML (`rules/`) definem *o que* deve ser o estado seguro, enquanto as primitivas em Python (`hardener/checks/`) executam *como* inspecionar e corrigir sem usar comandos em shell (`shell=False`). 

O ciclo operacional divide-se em:
- `audit`: inspeção somente leitura que aponta conformidade sem alterar nada.
- `enforce` (sem parâmetros): modo dry-run que simula ações sem tocar no disco.
- `enforce --apply`: aplicação real das mudanças com backup e validação.
- `rollback`: restauração transacional do estado anterior no sentido inverso.

Antes de qualquer alteração física, o `GerenciadorBackup` salva uma cópia fiel do arquivo original em `/var/lib/hardener/backups/<timestamp>/`. A gravação é **atômica** (o novo conteúdo é escrito em um arquivo `.tmp` no mesmo diretório, ajustadas as permissões e substituído via chamada de sistema `os.replace`), garantindo que falhas elétricas não corrompam os arquivos. Como proteção operacional contra execuções acidentais fora do laboratório, o `--apply` exige a presença da trava sentinela `/etc/hardener-vm`.

---

## 2. Mapa da Trilha B

| ID | O que verifica | Primitiva usada | Parâmetros do YAML | Arquivo e função onde está o código | Corrige sozinha ou só audita? | Arquivo de teste |
|---|---|---|---|---|---|---|
| **SSH-002** | Permissões e dono de `/etc/ssh/sshd_config` (0600 root:root) | `permissao_arquivo` | `caminho: /etc/ssh/sshd_config`, `modo_max: "0600"`, `dono: root`, `grupo: root` | `hardener/checks/permissao_arquivo.py` (`PermissaoArquivo.verificar` / `corrigir`) | Corrige sozinha | `tests/test_permissao_arquivo.py` |
| **PERM-002** | Permissões e dono de `/etc/passwd` (0644 root:root) | `permissao_arquivo` | `caminho: /etc/passwd`, `modo_max: "0644"`, `dono: root`, `grupo: root` | `hardener/checks/permissao_arquivo.py` (`PermissaoArquivo.verificar` / `corrigir`) | Corrige sozinha | `tests/test_permissao_arquivo.py` |
| **PERM-003** | Permissões e dono de `/etc/shadow` (0000 root:root) | `permissao_arquivo` | `caminho: /etc/shadow`, `modo_max: "0000"`, `dono: root`, `grupo: root` | `hardener/checks/permissao_arquivo.py` (`PermissaoArquivo.verificar` / `corrigir`) | Corrige sozinha | `tests/test_permissao_arquivo.py` |
| **PAM-001** | Tentativas máximas inválidas (`deny = 5`) no faillock | `arquivo_chave_valor` | `arquivo: /etc/security/faillock.conf`, `chave: deny`, `valor: "5"` | `hardener/checks/arquivo_chave_valor.py` (`ArquivoChaveValor.verificar` / `corrigir`) | Corrige sozinha | `tests/test_arquivo_chave_valor.py` |
| **PAM-001b** | Tempo de bloqueio de conta (`unlock_time = 900`) no faillock | `arquivo_chave_valor` | `arquivo: /etc/security/faillock.conf`, `chave: unlock_time`, `valor: "900"` | `hardener/checks/arquivo_chave_valor.py` (`ArquivoChaveValor.verificar` / `corrigir`) | Corrige sozinha | `tests/test_arquivo_chave_valor.py` |
| **PAM-002** | Comprimento mínimo de senha (`minlen = 14`) no pwquality | `arquivo_chave_valor` | `arquivo: /etc/security/pwquality.conf`, `chave: minlen`, `valor: "14"` | `hardener/checks/arquivo_chave_valor.py` (`ArquivoChaveValor.verificar` / `corrigir`) | Corrige sozinha | `tests/test_arquivo_chave_valor.py` |
| **ACC-002** | Máscara padrão de criação de arquivos (`UMASK 027`) em login.defs | `arquivo_chave_valor` | `arquivo: /etc/login.defs`, `chave: UMASK`, `valor: "027"`, `separador: " "` | `hardener/checks/arquivo_chave_valor.py` (`ArquivoChaveValor.verificar` / `corrigir`) | Corrige sozinha | `tests/test_arquivo_chave_valor.py` |
| **SUDO-001** | Proíbe cláusula `NOPASSWD` em sudoers e sudoers.d | `sudoers` | `proibir: nopasswd`, `recarregar: sudoers` | `hardener/checks/sudoers.py` (`Sudoers.verificar` / `corrigir`) | Corrige sozinha (comenta linhas) | `tests/test_sudoers.py` |
| **SUDO-002** | Proíbe diretiva `ALL` irrestrita para quem não for root/%wheel | `sudoers` | `proibir: all`, `permitidos: [root, "%wheel"]`, `recarregar: sudoers` | `hardener/checks/sudoers.py` (`Sudoers.verificar` / `corrigir`) | Corrige sozinha (comenta linhas) | `tests/test_sudoers.py` |
| **SUDO-003** | Membros secundários de `wheel` restritos à lista homologada | `conta_usuario` | `modo: membros_grupo`, `grupo: wheel`, `permitidos: [root, admin_ati, secops]` | `hardener/checks/conta_usuario.py` (`ContaUsuario.verificar` / `corrigir`) | Corrige sozinha (`gpasswd -d`) | `tests/test_conta_usuario.py` |
| **ACC-001** | Unicidade de UID 0 (apenas conta `root` permitida) | `conta_usuario` | `modo: uid0_unico` | `hardener/checks/conta_usuario.py` (`ContaUsuario._verificar_uid0_unico`) | **Só audita** (levanta ErroPrimitiva) | `tests/test_conta_usuario.py` |
| **PERM-001** | Auditoria de binários SUID/SGID contra a baseline oficial (32 itens) | `suid_sgid` | `permitidos: [32 caminhos absolutos]` | `hardener/checks/suid_sgid.py` (`SuidSgid.verificar`) | **Só audita** (levanta ErroPrimitiva) | `tests/test_suid_sgid.py` |
| **OFF-001** | Bloqueio de senha e expiração de contas não autorizadas | `offboarding` | CLI `--autorizados <csv>` | `hardener/offboarding.py` (`avaliar_offboarding` / `aplicar_offboarding`) | Corrige sozinha (`usermod -L`, `chage -E 0`) | `tests/test_offboarding.py` |
| **OFF-002** | Configuração de shell inerte `/sbin/nologin` em contas desativadas | `offboarding` | CLI `--autorizados <csv>` | `hardener/offboarding.py` (`avaliar_offboarding` / `aplicar_offboarding`) | Corrige sozinha (`usermod -s`) | `tests/test_offboarding.py` |
| **OFF-003** | Arquivamento preventivo de arquivos `authorized_keys` | `offboarding` | CLI `--autorizados <csv>` | `hardener/offboarding.py` (`avaliar_offboarding` / `aplicar_offboarding`) | Corrige sozinha (`shutil.move`) | `tests/test_offboarding.py` |
| **OFF-004** | Remoção de contas não autorizadas do grupo administrativo `wheel` | `offboarding` | CLI `--autorizados <csv>` | `hardener/offboarding.py` (`avaliar_offboarding` / `aplicar_offboarding`) | Corrige sozinha (`gpasswd -d`) | `tests/test_offboarding.py` |
| **OFF-005** | Encerramento de processos e sessões ativas de contas desativadas | `offboarding` | CLI `--autorizados <csv>` | `hardener/offboarding.py` (`avaliar_offboarding` / `aplicar_offboarding`) | Corrige sozinha (`loginctl` / `pkill`) | `tests/test_offboarding.py` |
| **OFF-006** | Relatório de contas regulares inativas há mais de 90 dias | `offboarding` | CLI `--autorizados <csv>` | `hardener/relatorios_contas.py` (`relatorio_contas_inativas`) | **Só audita** | `tests/test_offboarding_relatorios.py` |
| **OFF-007** | Relatório de contas ativas com senhas que nunca expiram | `offboarding` | CLI `--autorizados <csv>` | `hardener/relatorios_contas.py` (`relatorio_senhas_sem_expiracao`) | **Só audita** | `tests/test_offboarding_relatorios.py` |
| **OFF-008** | Relatório de chaves SSH órfãs ou associadas a contas bloqueadas | `offboarding` | CLI `--autorizados <csv>` | `hardener/relatorios_contas.py` (`relatorio_chaves_ssh_sem_dono`) | **Só audita** | `tests/test_offboarding_relatorios.py` |

---

## 3. Explicação Detalhada por Primitiva

### 3.1. `sudoers` (`hardener/checks/sudoers.py`)
- **O que faz:** Audita regras no arquivo `/etc/sudoers` e no diretório `/etc/sudoers.d/`, localizando permissões perigosas como `NOPASSWD` ou concessão de `ALL` a usuários não homologados. Na correção, desativa cirurgicamente cada regra ofensiva comentando-a com `# hardener: desativado: `, mantendo permissões estritas 0440. Garante a integridade do sistema testando a sintaxe com `visudo -cf` antes de substituir o arquivo original.
- **Fluxo de execução:** `verificar()` chama `_encontrar_violacoes()`, que lista os arquivos relevantes via `_listar_arquivos_sudoers()` (ignorando arquivos com ponto ou terminados em `~`), desfaz quebras de linha com `_ler_instrucoes()` e inspeciona o texto com `_eh_regra_violadora()`. O `corrigir()` chama `_encontrar_violacoes()`, aciona `ctx.salvar_antes_de_alterar()`, prefixa as linhas violadoras na memória, grava em um arquivo `.tmp` na mesma pasta, executa `ctx.runner.executar(["visudo", "-cf", tmp])`, aplica `os.chmod(0o440)` e substitui o arquivo com `os.replace()`.
- **Decisões de segurança:** A validação com `visudo -cf` no temporário antes do `os.replace` impede que um erro de sintaxe inutilize o binário `sudo` da máquina (o que travaria o acesso root de toda a equipe). Salva backup prévio antes da escrita. Ignora arquivos com ponto ou til conforme a convenção do próprio utilitário sudo.
- **Tratamento de erros:** Se o `visudo -cf` reprovar o temporário, o código remove o `.tmp` (`tmp.unlink()`) e levanta `ErroPrimitiva("validação visudo falhou...")`. O motor captura essa exceção e marca a regra com `Status.FALHOU`, deixando o arquivo de produção intocado.
- **Limites conhecidos:** Conforme documentado na docstring, não interpreta aliases complexos (`User_Alias`, `Runas_Alias`, `Host_Alias`, `Cmnd_Alias`) nem negações gramaticais aninhadas.

### 3.2. `conta_usuario` (`hardener/checks/conta_usuario.py`)
- **O que faz:** Inspeciona contas e grupos locais para evitar persistência indevida e escalonamento de privilégios. No modo `uid0_unico`, garante que apenas o usuário `root` possua o identificador de superusuário UID 0. No modo `membros_grupo`, compara os membros do grupo `wheel` com a lista autorizada e expulsa invasores via utilitários oficiais do sistema.
- **Fluxo de execução:** `verificar()` despacha para `_verificar_uid0_unico()` (lê `/etc/passwd` e filtra quem tem campo UID igual a 0) ou para `_verificar_membros_grupo()` (lê `/etc/group` e obtém o campo 4 de membros secundários). O `corrigir()` levanta `ErroPrimitiva` imediato no modo `uid0_unico`; no modo `membros_grupo`, aciona `ctx.salvar_antes_de_alterar()` para `/etc/group` E `/etc/gshadow`, e para cada usuário extra executa `ctx.runner.executar(["gpasswd", "-d", usuario, grupo])`.
- **Decisões de segurança:** Não há correção automática para UID 0 porque alterar ou deletar um superusuário às cegas pode quebrar a titularidade de arquivos e serviços críticos no SO. O backup simultâneo de `/etc/group` e `/etc/gshadow` impede que a base de grupos fique inconsistente. O usuário `root` é mantido fixo no conjunto de autorizados, mesmo se omitido na política YAML.
- **Tratamento de erros:** Se o `/etc/passwd` ou `/etc/group` não existirem, ou se o grupo não for encontrado, levanta `ErroPrimitiva`. Se o comando `gpasswd -d` retornar código de falha (`not r.ok`), interrompe o fluxo levantando `ErroPrimitiva` com a mensagem do erro.
- **Limites conhecidos:** Usuários cujo GID primário em `/etc/passwd` seja o do grupo alvo não constam no campo 4 de membros secundários do `/etc/group`, não sendo auditados ou removidos por essa primitiva.

### 3.3. `permissao_arquivo` (`hardener/checks/permissao_arquivo.py`)
- **O que faz:** Audita e ajusta permissões octais (`modo_max`) e propriedade (`dono:grupo`) de arquivos e diretórios essenciais. Na correção, aplica operações bitwise para assegurar que privilégios nunca sejam aumentados, apenas restringidos. Possui suporte adicional para auditoria de arquivos world-writable sem sticky bit (`auditar_world_writable`) e varredura recursiva de diretórios.
- **Fluxo de execução:** `verificar()` obtém atributos via `stat()` (`_obter_usuario`, `_obter_grupo`), comparando o modo atual com `modo_max` através da máscara `modo_atual & ~modo_max_val != 0`. O `corrigir()` calcula `novo_modo = modo_atual & modo_max_val`, chama `ctx.salvar_antes_de_alterar()` para arquivos regulares, invoca `os.chmod()` para ajustar permissões e `_resolver_uid()` / `_resolver_gid()` para aplicar `os.chown()`.
- **Decisões de segurança:** Princípio do mínimo privilégio garantido matematicamente: o cálculo `modo_atual & modo_max_val` (E lógico) desliga bits proibidos mas **nunca adiciona permissões** que o arquivo não tinha (um arquivo `0400` com `modo_max: 0644` permanece `0400`, jamais sobe para `0644`). O modo `auditar_world_writable` levanta `ErroPrimitiva` na correção para impedir exclusão desastrosa de arquivos públicos em `/tmp`.
- **Tratamento de erros:** Se o arquivo não existir (e `criar_se_ausente` for falso), se o dono ou grupo informados não existirem no sistema operacional, ou se `chmod`/`chown` dispararem `OSError`, levanta `ErroPrimitiva`.
- **Limites conhecidos:** A resolução de nomes depende das chamadas C locais `pwd` e `grp`; contas gerenciadas exclusivamente por diretórios externos LDAP/Active Directory podem falhar caso o cache NSS não esteja ativo.

### 3.4. `arquivo_chave_valor` (`hardener/checks/arquivo_chave_valor.py`)
- **O que faz:** Gerencia arquivos de configuração formados por pares de chave e valor (como `faillock.conf`, `pwquality.conf` e `login.defs`). Na verificação, percorre o arquivo respeitando comentários e identifica o valor da última ocorrência da chave. Na correção, substitui a linha correspondente in-place ou a anexa ao final de forma atômica, preservando o modo octal do arquivo original.
- **Fluxo de execução:** `verificar()` lê as linhas do arquivo e aplica `_analisar_linha()` com separador configurável (`" = "` ou `" "`), capturando o último valor não comentado. O `corrigir()` checa a conformidade (se já estiver correto, retorna lista vazia imediatamente), chama `ctx.salvar_antes_de_alterar()`, preserva o modo octal original via `stat()`, atualiza a linha na memória, escreve no `.tmp`, aplica `os.chmod(modo_original)` e substitui via `os.replace()`.
- **Decisões de segurança:** Adota a regra de que a última declaração no arquivo prevalece, comportamento idêntico ao dos parsers do PAM e do Linux. A preservação explícita do modo octal original evita que arquivos sensíveis percam permissões restritivas ao serem reescritos. Gravação atômica via `.tmp` e `os.replace`.
- **Tratamento de erros:** Arquivo inexistente ou falha de leitura em `verificar()` retorna `Verificacao(conforme=False)` amigável para o relatório. Falhas de disco na gravação disparam exceção capturada pelo motor como `Status.FALHOU`.
- **Limites conhecidos:** Não processa arquivos formatados com seções INI (como `[secao]`), configurações em bloco XML/JSON ou múltiplas chaves repetidas que possuam semântica cumulativa.

### 3.5. `suid_sgid` (`hardener/checks/suid_sgid.py`)
- **O que faz:** Inspeciona o sistema de arquivos local à procura de executáveis que contenham bits especiais SUID (`04000`) ou SGID (`02000`) fora de uma lista estrita de 32 binários homologados. Opera estritamente dentro da partição raiz sem cruzar pontos de montagem externos (`find -xdev`) e descarta diretórios virtuais do kernel. Por segurança absoluta, opera exclusivamente como auditoria passiva.
- **Fluxo de execução:** `verificar()` obtém o dispositivo da raiz (`raiz.stat().st_dev`) e percorre a árvore via `os.walk(..., followlinks=False, onerror=on_walk_error)`. Descarta diretórios iniciados pelos prefixos `/proc`, `/sys`, `/dev` e `/run`, além de subpastas com `st_dev` diferente da raiz. Para cada arquivo regular que possua bits SUID/SGID, valida se o caminho consta no conjunto `permitidos`. Se houver mais de 20 violações, formata o campo `atual` com os 20 primeiros e indica o total restante. O `corrigir()` levanta diretamente `ErroPrimitiva("sem correção automática: revisar manualmente")`.
- **Decisões de segurança:** Não seguir links simbólicos (`followlinks=False`) e limitar a busca ao mesmo `st_dev` evita loops infinitos e travamentos ao varrer compartilhamentos NFS ou sistemas de arquivos temporários. Nunca remove os bits automaticamente, pois desativar SUID de utilitários como `passwd` ou `sudo` danificaria o login e a administração da máquina.
- **Tratamento de erros:** Erros de permissão ao ler diretórios ou arquivos protegidos não abortam a execução: são interceptados pelo callback `on_walk_error`, somados no contador `erros_perm` e reportados no campo `detalhe` da verificação.
- **Limites conhecidos:** Links simbólicos para binários SUID não são avaliados, partições secundárias montadas fora da raiz são ignoradas e diretórios inacessíveis para o usuário executor não são abertos.

---

## 4. Módulo Especializado de Offboarding

Implementado em `hardener/offboarding.py` e `hardener/relatorios_contas.py`:

### 4.1. Passos para Identificar Contas Não Autorizadas
1. A função `carregar_autorizados_csv()` lê o CSV (`demo/dados/autorizados.csv`), detecta dinamicamente a coluna de usuário (`usuario`, `user` ou índice 0), descarta registros com status "desligado", "inativo" ou "desativado", e adiciona `root`.
2. A função `listar_usuarios_locais()` lê `/etc/passwd` e extrai usuários regulares com UID >= 1000 (ignorando `nobody` e `nfsnobody`).
3. Compara as listas: qualquer usuário presente em `/etc/passwd` ausente do CSV é enquadrado como conta não autorizada.

### 4.2. Cinco Ações Defensivas em Ordem Estrita
1. **Bloqueio e Expiração (OFF-001):** Executa `usermod -L <user>` (insere `!` na senha do `/etc/shadow`) e `chage -E 0 <user>` (expira a conta imediatamente).
2. **Shell Inerte (OFF-002):** Executa `usermod -s /sbin/nologin <user>` para desativar qualquer shell interativo.
3. **Arquivamento de Chaves SSH (OFF-003):** Move o arquivo pontual `~/.ssh/authorized_keys` da conta para `/var/backups/revoked_ssh_keys/<user>_authorized_keys_<sessao_id>` com `shutil.move()`, impedindo login por chave pública.
4. **Revogação de Privilégios (OFF-004):** Executa `gpasswd -d <user> wheel`, removendo a conta do grupo administrativo.
5. **Encerramento de Sessões (OFF-005):** Executa `loginctl terminate-user <user>` (com fallback para `pkill -9 -u <user>`), desconectando o usuário do sistema.

### 4.3. Salvaguardas do Operador e Integridade
- **Guarda do Operador:** A função `_obter_usuario_execucao()` inspeciona a variável de ambiente `SUDO_USER` ou `os.geteuid()`. Se o operador executor for diferente de `root` e não constar no CSV de autorizados, o código aborta imediatamente levantando `ErroOffboarding` antes de aplicar qualquer alteração, prevenindo auto-lockout.
- **Guarda da Lista Vazia:** Se a lista do CSV contiver exclusivamente o usuário `root`, `carregar_autorizados_csv()` levanta `ErroOffboarding` e cancela a operação para evitar desativação em massa de todas as contas corporativas do servidor.

### 4.4. Idempotência
A função `_carregar_shadow()` e os testes de sistema verificam previamente se a conta já está com `!`, se a expiração é 0, se o shell já é `nologin`, se a chave SSH já foi movida e se a conta não está mais no `wheel`. Em uma segunda execução imediata, o código detecta que nenhuma ação é necessária (`tem_acoes_pendentes == False`) e retorna sem alterar arquivos, sem chamar comandos de sistema e sem gerar novas sessões de backup.

### 4.5. Relatórios Forenses Complementares (Somente Auditoria)
- **OFF-006 (`relatorio_contas_inativas`):** Executa `lastlog` para identificar usuários com UID >= 1000 que nunca realizaram login ou cujo último acesso ocorreu há mais de 90 dias.
- **OFF-007 (`relatorio_senhas_sem_expiracao`):** Inspeciona `/etc/shadow` filtrando contas ativas cuja validade máxima da senha (campo 5) esteja vazia ou configurada como `99999`.
- **OFF-008 (`relatorio_chaves_ssh_sem_dono`):** Varre arquivos `authorized_keys` em `/root` e `/home/*`, identificando chaves cujo UID não existe mais em `/etc/passwd` ou cujas contas associadas estão bloqueadas ou com shell `/sbin/nologin`.

---

## 5. Como as Peças se Conectam

1. **CLI:** O usuário aciona os subcomandos via terminal (`hardener/cli.py`).
2. **Política:** `policy.py` (`carregar_politica`) lê os arquivos em `rules/*.yaml` via PyYAML, valida o schema estrutural e instancia objetos `Regra`.
3. **Motor Central:** `engine.py` (`Motor`) recebe as regras e o `Contexto` (contendo `runner`, `raiz` e `GerenciadorBackup`).
4. **Despacho para Primitiva:** O motor localiza a primitiva no dicionário `REGISTRO` (`hardener/checks/__init__.py`) e invoca `prim.verificar(regra.parametros, ctx)`.
5. **Correção e Backup:** Se o comando for `enforce --apply` e a regra estiver `NAO_CONFORME`, o motor chama `prim.corrigir(regra.parametros, ctx)`. A primitiva aciona `ctx.salvar_antes_de_alterar()`, salvando o arquivo na sessão de backup antes de gravar no disco. Após a correção, re-executa `prim.verificar()` para atestar o status `CORRIGIDO`.
6. **Validação e Recarga de Serviços:**
   - As regras SUDO-001 e SUDO-002 declaram no YAML a diretiva `recarregar: sudoers`.
   - O motor executa `_validar_e_recarregar()`, chamando `rhel.validar_servico(runner, "sudoers")`, que executa com sucesso `visudo -c`.
   - **Gargalo Atual:** Em seguida, o motor chama `rhel.recarregar_servico(runner, "sudoers")`. Como `hardener/rhel.py` executa cegamente `systemctl reload <servico>`, o comando `systemctl reload sudoers` falha no Linux real (sudoers não é daemon). Ao receber erro de recarga, o motor dispara `sessao.restaurar(servico="sudoers")`, revertendo as alterações no sudoers e marcando as regras como `Status.FALHOU`.

---

## 6. Conferência de Documentação vs Código Real

1. **Arquivamento de `authorized_keys`:**
   - *Texto:* `description.md` (linha 355) afirma: *"Move recursivamente o arquivo `~/.ssh/authorized_keys` da conta para `/var/backups/revoked_ssh_keys/`"*.
   - *Código:* Em `hardener/offboarding.py` (linhas 363-368), o código move um único arquivo pontual via `shutil.move()`, renomeando-o para `<user>_authorized_keys_<sessao_id>`.
   - *Classificação:* Erro do texto do `description.md` (termo "recursivamente" inadequado para um arquivo individual).
2. **Cobertura de violações em `demo/sujar_servidor.sh`:**
   - *Texto:* `description.md` (linhas 184 e 387) afirma que o script cria todas as violações na VM.
   - *Código:* Todas as violações da Trilha B são criadas, **exceto a regra PERM-002** (`/etc/passwd` com modo 0644). O script insere `toor_demo`, mas não altera as permissões do arquivo para algo permissivo como 0666.
   - *Classificação:* Lacuna do código em `demo/sujar_servidor.sh`.
3. **Comportamento de `recarregar: sudoers`:**
   - *Texto:* `description.md` pressupõe que `recarregar_servico` apenas valida com `visudo -c` e não tenta dar reload em sudoers.
   - *Código:* `rhel.py` (linha 46) roda `systemctl reload sudoers`. No `engine.py`, ao detectar a falha desse comando, aciona o rollback das alterações de sudoers.
   - *Classificação:* Lacuna do código do Aluno A (necessário ajustar `rhel.py` para não dar reload no sudoers).
4. **Existência do campo `somente_auditoria`:**
   - *Texto:* Mencionado no `description.md` como mecanismo do motor.
   - *Código:* Não existe em `models.py` (`Regra`), nem em `policy.py` (`CAMPOS_CONHECIDOS`), nem no loop de `engine.py`. Em `rules/accounts.yaml`, aparece apenas como comentário.
   - *Classificação:* Lacuna do código do Aluno A (o motor ainda não suporta o campo nativamente no YAML).
5. **Status das referências CIS Benchmark:**
   - *Texto e Código:* Todas as 11 regras ativas da Trilha B terminam a referência com `(A CONFIRMAR o item no benchmark)`. Na tabela `docs/TABELA_DOR_REGRA_CIS.md`, todas as colunas de CIS permanecem marcadas como `A CONFIRMAR`.
   - *Classificação:* Pendência formal de documentação prevista no escopo.

---

## 7. Pendências e Riscos

### 7.1. O que ainda não foi validado na VM Real (Checklist de `VALIDAR_NA_VM.md`)
- SSH-002, PERM-002 e PERM-003: validação de permissões com `stat`, ciclo de enforce e rollback sem quebrar logins.
- PAM-001, PAM-001b, PAM-002: teste de bloqueio de conta e checagem da compatibilidade da pilha com `authselect current`.
- ACC-002: validação prática se o umask 027 é herdado por novos processos de usuários criados.
- SUDO-001, SUDO-002 e SUDO-003: validação de que o `sudo -l` continua funcionando para usuários homologados e que o `%wheel` não perde privilégios.
- ACC-001 e PERM-001: detecção na VM suja com os binários reais.
- OFF-001 a OFF-005: teste do bloqueio de chave real com `ssh -i /root/ex_funcionario_demo_key ex_funcionario@localhost`.
- OFF-006: conferência do formato exato de saída do utilitário `lastlog` no RHEL 9.8.

### 7.2. O que depende dos outros integrantes
- **Aluno A:**
  1. Ajustar `hardener/rhel.py` e `hardener/engine.py` para não tentar executar `systemctl reload sudoers`.
  2. Adicionar o campo `somente_auditoria: bool` em `models.py` (`Regra`), incluí-lo em `CAMPOS_CONHECIDOS` em `policy.py` e tratá-lo no `engine.py`.
- **Pessoa C (ou operador da VM):**
  1. Executar os procedimentos práticos na VM oficial RHEL 9.8 com snapshot e marcar os checkboxes de `VALIDAR_NA_VM.md`.
  2. Validar se a saída de `find / -xdev -type f \( -perm -4000 -o -perm -2000 \) | sort` na VM limpa bate 100% com os 32 itens de `docs/baseline_suid_sgid_rhel9.txt`.
  3. Consultar o CIS Benchmark RHEL 9 oficial e substituir os textos `A CONFIRMAR`.

### 7.3. Os 5 Maiores Riscos de Falha no `enforce --apply`
1. **Reversão indesejada de regras de sudoers:** Se o Aluno A não tratar o reload do sudoers, o `systemctl reload sudoers` falhará e o motor reverterá o arquivo de sudoers, gerando falso status de `FALHOU`.
2. **Auto-lockout do operador durante o offboarding:** Se o operador estiver logado via SSH com uma conta local não listada no CSV e sem sessão root secundária, o offboarding mudará o shell para `/sbin/nologin` e encerrará sua sessão imediatamente.
3. **Bloqueio acidental no PAM (`faillock`):** A ativação de `deny = 5` com `unlock_time = 900` pode bloquear o acesso de administradores durante testes automatizados se houver falhas repetidas de autenticação.
4. **Quebra de utilitários locais por permissão `0000` em `/etc/shadow` (PERM-003):** O modo `0000` é padrão estrito no RHEL 9 (que depende de binários setuid como `unix_chkpwd`), mas scripts ou agentes de monitoramento antigos que rodem sem privilégios podem quebrar.
5. **Inconsistência de grupos em `/etc/group`:** A remoção de usuários do grupo `wheel` via `gpasswd -d` pode impedir que colaboradores que necessitam de privilégios de manutenção consigam executar comandos administrativos se o arquivo `demo/dados/autorizados.csv` estiver desatualizado.

---

## 8. Preparação para a Banca

### 8.1. 10 Perguntas Difíceis da Banca e Respostas Rápidas

1. **Pergunta:** Por que na primitiva `permissao_arquivo` vocês usam uma operação de bitwise AND (`modo_atual & modo_max`) em vez de simplesmente atribuir o `modo_max` no `chmod`?  
   **Resposta:** Para respeitar o princípio de nunca conceder privilégios adicionais. O E lógico apenas remove bits excedentes; se um arquivo tinha permissão restritiva `0400` e a regra exige `modo_max 0644`, ele permanece `0400`, sem receber permissões de escrita ou leitura para grupos que não possuía.

2. **Pergunta:** O que impede o comando de offboarding de desativar a conta do próprio administrador que está executando o comando?  
   **Resposta:** A guarda de segurança em `_obter_usuario_execucao()`: ela lê a variável de ambiente `SUDO_USER` (ou o UID efetivo) e, caso o operador não conste no CSV de autorizados, aborta a execução levantando `ErroOffboarding` antes de aplicar qualquer alteração.

3. **Pergunta:** Por que as regras ACC-001 (UID 0 único) e PERM-001 (SUID/SGID) levantam exceção `ErroPrimitiva` no método `corrigir()` em vez de removerem o usuário ou retirarem o bit SUID?  
   **Resposta:** Porque alterar UIDs de superusuários ou remover bits SUID de binários essenciais sem triagem contextual pode quebrar completamente a inicialização e operabilidade do sistema operacional. São regras estritas de auditoria passiva.

4. **Pergunta:** Como a primitiva `sudoers` garante que uma alteração não vai corromper a sintaxe do sudo e bloquear o acesso administrativo de toda a equipe?  
   **Resposta:** Antes de tocar no arquivo real, ela gera o conteúdo em um arquivo temporário `.tmp` na mesma pasta e roda `visudo -cf <tmp>`. Se a sintaxe for reprovada, o temporário é excluído e a primitiva falha sem encostar no arquivo de produção.

5. **Pergunta:** O que acontece se o operador executar o comando `enforce --apply` duas vezes consecutivas?  
   **Resposta:** O sistema é completamente idempotente. Na segunda execução, a etapa de verificação constata que o sistema já está conforme, nenhum arquivo é reescrito, nenhuma pasta de backup adicional é criada e nenhum comando de recarga é disparado.

6. **Pergunta:** Se um usuário tiver o grupo `wheel` configurado como seu grupo primário no `/etc/passwd`, a primitiva `conta_usuario` vai removê-lo?  
   **Resposta:** Não. Conforme declarado na docstring da primitiva, ela audita o campo 4 de membros secundários do `/etc/group`. Usuários com o grupo como primário não aparecem nessa lista, sendo esse um limite documentado do design.

7. **Pergunta:** O offboarding apaga as chaves SSH do usuário desligado?  
   **Resposta:** Não apaga. O código primeiro salva uma cópia na sessão de backup do hardener e depois move o arquivo `authorized_keys` para `/var/backups/revoked_ssh_keys/` via `shutil.move()`, preservando a evidência forense e permitindo restauração posterior.

8. **Pergunta:** Por que chamadas ao sistema usam `ctx.runner.executar(["cmd", "arg"])` em vez de `os.system` ou `subprocess.run(shell=True)`?  
   **Resposta:** Para extinguir o risco de injeção de comandos via shell e possibilitar que 100% dos testes unitários rodem em milissegundos sem privilégios de root, utilizando a fixture `FakeRunner` para interceptar comandos.

9. **Pergunta:** Por que a primitiva `suid_sgid` compara o identificador `st_dev` durante a varredura?  
   **Resposta:** Para emular a flag `-xdev` do utilitário `find`, impedindo que a busca cruze sistemas de arquivos montados (como `/boot`, partições de rede NFS ou memória temporária), restringindo a auditoria estritamente ao disco raiz.

10. **Pergunta:** O que o sistema faz se o CSV de colaboradores autorizados contiver apenas a linha do usuário `root`?  
    **Resposta:** A função `carregar_autorizados_csv()` possui uma guarda explícita que detecta se `autorizados == {"root"}` e levanta `ErroOffboarding`, abortando a operação para evitar a desativação acidental de todas as contas corporativas do servidor.

---

### 8.2. Roteiro de 3 Minutos para a Apresentação da Trilha B

- **Minuto 1: Contexto e Dores da ATI (Identidade e Privilégio)**  
  *"Boa tarde. Na Trilha B, nosso foco foi sanar as dores 5 e 6 da ATI: a persistência de contas de colaboradores desligados e a concessão frouxa de privilégios administrativos no RHEL 9. Construímos uma arquitetura desacoplada: as políticas são declaradas em YAML (`rules/accounts.yaml`), e a execução ocorre através de 5 primitivas Python especializadas e um módulo dedicado de offboarding."*

- **Minuto 2: Princípios de Segurança e Engenharia de Software**  
  *"Nossa prioridade absoluta foi a segurança operacional: nenhuma alteração de arquivo é feita sem backup prévio em `/var/lib/hardener/backups/`, as gravações são atômicas via `os.replace` e alterações de sudoers passam obrigatoriamente por `visudo -cf` antes da escrita. Na redução de privilégios de arquivos, usamos cálculo bitwise para garantir que permissões nunca sejam aumentadas. E no offboarding, neutralizamos contas desativadas em 5 camadas (bloqueio, expiração, shell nologin, arquivamento de chaves SSH e encerramento de processos), sempre protegendo a conta do operador via `SUDO_USER`."*

- **Minuto 3: Demonstração Prática no Terminal**  
  *"Executamos agora os comandos no terminal para demonstrar a solução funcionando:"*
  ```bash
  # 1. Mostrar validação estática de regras
  python3 -m hardener validar

  # 2. Executar auditoria na VM com violações
  sudo python3 -m hardener audit --dor 6

  # 3. Demonstrar simulação segura de offboarding (dry-run)
  sudo python3 -m hardener offboarding --autorizados demo/dados/autorizados.csv

  # 4. Aplicar o hardening real com criação de backup
  sudo python3 -m hardener enforce --apply --dor 6

  # 5. Provar a idempotência imediata
  sudo python3 -m hardener enforce --apply --dor 6
  ```
  *"Como demonstrado, o segundo enforce não altera nenhum byte e comprova conformidade total. Estamos abertos a perguntas."*

---

## 9. O que Preciso Confirmar com o Aluno A ou Testar na VM

- **Confirmar com o Aluno A:**
  1. O ajuste em `hardener/rhel.py` e `hardener/engine.py` para tratar `recarregar: sudoers` apenas validando com `visudo -c` sem tentar invocar `systemctl reload sudoers`.
  2. A implementação do suporte formal ao campo `somente_auditoria` em `models.py`, `policy.py` e `engine.py`, permitindo que regras de auditoria pura (ACC-001, PERM-001) sejam declaradas sem depender de exceções.
- **Testar na VM:**
  1. Rodar `demo/sujar_servidor.sh` e executar o checklist completo de `VALIDAR_NA_VM.md` (audit, enforce, segundo enforce e rollback).
  2. Testar na prática se a tentativa de login com a chave SSH gerada (`ssh -i /root/ex_funcionario_demo_key ex_funcionario@localhost`) é recusada imediatamente após o offboarding.
  3. Rodar `find / -xdev -type f \( -perm -4000 -o -perm -2000 \) | sort` no snapshot limpo para confirmar a baseline de 32 binários do RHEL 9.8.
  4. Abrir o PDF oficial do CIS Benchmark RHEL 9 e substituir todas as menções a `(A CONFIRMAR o item no benchmark)`.
