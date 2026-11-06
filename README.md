# server-baseline

Padrão inicial para servidores **Ubuntu 24.04 LTS** (qualquer 24.04.x): atualização, IPv6, SSH por chave,
UFW e SNMPv3, com verificação. Interativo, **sem dados fixos**: redes, chave, portas e SNMP são perguntados,
com explicação, exemplo e padrão.

Serve de base para qualquer servidor. Programas instalados depois (ex.: um resolvedor DNS) abrem as próprias
portas no UFW; o baseline só mexe nas regras marcadas `# baseline:`.

## O que ele faz

| Etapa | O que aplica |
|---|---|
| 1. Sistema | **disco**: se o LV da raiz (LVM) é menor que o disco e sobra > 1 GB no grupo, oferece `lvextend -r -l +100%FREE`; **relógio**: confere `NTPSynchronized` e o serviço de hora (timesyncd ou chrony, **sem trocar um pelo outro**), esperando até 60 s; fuso horário, nome do servidor, `apt full-upgrade` (opcional), atualização automática diária **só de segurança, sem reboot automático**, no horário escolhido, com lista de pacotes que ela não toca (ex.: `unbound`); **atalhos de terminal** (alias) para todos os usuários (opcional); **Ubuntu Pro** (Livepatch/ESM, opcional) |
| 2. IPv6 | sugere o /64 sozinho (prefixo anunciado pelo roteador, ou o AAAA de um vizinho da mesma rede IPv4 — ex.: o servidor DNS configurado), confere com o bloco do provedor, sugere `<prefixo>::<último octeto>` e **testa antes do resumo**: duplicidade (DAD) e resposta do gateway. Grava `/etc/netplan/60-ipv6.yaml` e já ativa, sem reboot |
| 3. SSH + UFW | porta própria, só chave, sem root; **AllowUsers** (padrão: só o administrador), **AllowTcpForwarding no**, **AllowAgentForwarding no**, `LoginGraceTime 30`, `ClientAliveInterval 300`, `ClientAliveCountMax 2` (cada um é perguntado); UFW nega a entrada e libera o SSH só para as redes de gestão. **Volta automática**: se o novo acesso não for confirmado em 5 minutos, SSH e UFW voltam ao que eram |
| 4. SNMPv3 | somente leitura, `authPriv` (SHA-256/AES), sem community; porta 161 só para o monitoramento |

As respostas (sem senha) ficam em `/root/baseline.env` e viram o padrão da próxima execução.
Cópias do que foi alterado: `/root/baseline-backup-<data>/`. Log: `/root/baseline-<data>.log` (veja "Segurança").

## Antes de rodar

- Ubuntu Server 24.04 instalado com **IPv4 fixo** (endereço, gateway e DNS) e acesso à internet.
- Um usuário administrador com `sudo` (o criado na instalação).
- A sua **chave pública SSH** à mão (o login por senha será desligado).
- Para o SNMP: o IP do monitoramento, o usuário e as duas senhas que serão cadastradas nele.

## Como rodar

No servidor, baixe uma **versão marcada** (nunca a `main`), confira o SHA256 publicado na versão e execute:

```bash
cd /tmp
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/baseline.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/baseline-verify.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/SHA256SUMS
sha256sum -c SHA256SUMS                       # os dois têm de dar "OK"; compare também com a página da versão (Releases)
sudo bash baseline.sh
```

Sem internet no servidor: copie os dois arquivos para `/tmp` por `scp` e rode igual.

Ao final, **sem fechar a sessão**, abra uma conexão SSH nova na porta nova e digite `OK` no script.
Antes de pedir o OK, o script faz um **autoteste**: confere o `sshd -T` efetivo e faz um login real do administrador
na porta nova (chave efêmera, só pelo loopback, removida em seguida). Se falhar, SSH e UFW voltam na hora.
O `OK` só é aceito direto se o journal (`journalctl -u ssh.service`) mostrar um login do administrador por chave
vindo de um IP que **não** seja o loopback; sem isso o script avisa e exige um **segundo `OK`** (o autoteste local não conta).

### ⚠ Não reinicie o servidor antes do OK

A volta automática é um timer **temporário** do systemd (`systemd-run`, vive em `/run`): um **reboot antes do OK a desarma**
(nada mais desfaz sozinho). O SSH/UFW novos continuam valendo. O baseline deixa `/root/baseline-backup-<data>/PENDENTE`
até a confirmação; o `baseline-verify` e a próxima execução avisam "baseline nunca confirmado".

Se isso acontecer:

1. **O acesso novo funciona** (porta nova, chave, IP de gestão)? Rode `sudo baseline-verify` e depois `sudo bash baseline.sh`
   outra vez, confirmando com `OK` — isso limpa o aviso.
2. **Não entra?** Use o **console da VM** e desfaça: `sudo bash /root/baseline-backup-<data>/volta.sh`
   (restaura SSH e UFW de antes; o script fica no disco, sobrevive ao reboot).
3. Para saber se há volta armada neste momento: `systemctl list-timers 'baseline-volta-*'`.

Depois:

```bash
sudo reboot
sudo baseline-verify          # só leitura; saída 0 = tudo OK
```

## Endurecimento do SSH (perguntas)

Cada item tem explicação, exemplo e padrão seguro; a resposta anterior vira o padrão da próxima execução.

| Pergunta | Chave no `.env` | Padrão | Atenção |
|---|---|---|---|
| AllowUsers | `SSH_USUARIOS` | só o administrador | aceita vários (espaço ou vírgula); o administrador é obrigatório; contas de serviço (backup, rsync) perdem o SSH se não estiverem na lista |
| AllowTcpForwarding | `SSH_TCP_FWD` | `nao` | quebra `ssh -L/-R`, `ssh -J` (bastion) e VS Code Remote; não é barreira forte contra quem tem shell |
| AllowAgentForwarding | `SSH_AGENT_FWD` | `nao` | `ssh -A` deixa de funcionar a partir deste servidor |
| LoginGraceTime | `SSH_GRACE` | `30` | 5–600 s |
| ClientAliveInterval | `SSH_ALIVE_INT` | `300` | 0–3600 s; derruba conexão **morta**, não sessão parada |
| ClientAliveCountMax | `SSH_ALIVE_MAX` | `2` | 1–10 |

O `baseline-verify` confere esses itens pelo `sshd -T -C user=<admin>,…` (efetivo, com os blocos `Match`). O AllowUsers
é comparado como **conjunto exato**: um `AllowUsers` a mais em outro arquivo de `sshd_config.d` (a diretiva acumula) dá FALHA.
Servidores que rodaram a v2.0.0 ainda não têm essas chaves no `.env`: o verify mostra AVISO até você rodar o baseline de novo.

### Quando outro arquivo do SSH vence (o sshd usa a 1.ª ocorrência)

Outros produtos (ex.: o DNS Admin, com `01-dns-admin.conf`) também gravam em `/etc/ssh/sshd_config.d/`. Como o sshd vale a **1.ª ocorrência**
de cada diretiva e os arquivos são lidos em ordem de nome (e o `sshd_config` principal, antes do `Include`), um arquivo que ordena **antes** do
`10-baseline.conf` vence. **Antes do resumo** o baseline simula o sshd (`sshd -T -f`, sem aplicar nada) com o `10-baseline.conf` no lugar certo da
ordem de leitura e compara com o que você escolheu:

| Situação | O que acontece |
|---|---|
| **Conforto** (`ClientAliveInterval`, `ClientAliveCountMax`, `LoginGraceTime`) vencido por outro arquivo | **avisa no resumo** e segue: `SSH ClientAliveInterval: escolhido 300, mas 01-dns-admin.conf define 3 e VENCE (o sshd usa a 1.ª ocorrência)`. O autoteste passa a esperar o valor que **vence**, então outro produto vencendo não aborta |
| **Segurança** (`Port`, `PasswordAuthentication`, `KbdInteractiveAuthentication`, `PermitRootLogin`, `PubkeyAuthentication`, `AllowUsers`, `MaxAuthTries`, `X11Forwarding`, `AllowTcpForwarding`, `AllowAgentForwarding`) com valor **menos seguro** (inclusive `Port` ou `AllowUsers` **somados** por outro arquivo, que acumulam) | **para antes de aplicar**, nomeando o arquivo. Nada é alterado |
| Segurança com valor **mais restritivo** (ex.: `MaxAuthTries 2`) | avisa e segue |
| `sshd_config` sem o `Include` de `sshd_config.d` | para: o `10-baseline.conf` seria ignorado |
| Diferença **inesperada** depois de aplicar | o autoteste continua abortando e restaurando SSH/UFW |

O baseline **nunca edita nem move arquivo de outro produto**: ajuste a diretiva no arquivo indicado (ou escolha outro valor) e rode de novo.
O `baseline-verify` aplica a mesma regra: conforto vencido por outro arquivo é **AVISO** ("outro arquivo vence: …"), segurança menos segura é **FALHA** citando o arquivo.

## Disco, relógio, atalhos de terminal e Ubuntu Pro (perguntas)

Tudo aparece no **RESUMO** antes de "Aplicar?" e é conferido pelo `baseline-verify`.

| Pergunta / checagem | Chave no `.env` | Padrão | Atenção |
|---|---|---|---|
| Usar todo o disco para o sistema? | `DISCO_EXPANDIR` | `sim` | **só é perguntada** se a raiz está num LV e o grupo (VG) tem **mais de 1 GB livre** (`vgs -o vg_free`); aplica `lvextend -r -l +100%FREE <LV da raiz>` com o sistema ligado. Sem LVM ou sem espaço: nada, sem pergunta. Responda `n` se o espaço for para outro LV/snapshot. `baseline-verify`: AVISO se sobrar > 1 GB livre no VG da raiz |
| Relógio sincronizado | (não é pergunta) | — | confere `timedatectl show -p NTPSynchronized` e o serviço de hora ativo (systemd-timesyncd **ou** chrony). Não sincronizado: espera até 60 s; persistindo, AVISO no resumo ("DNSSEC e certificados dependem da hora certa"). **Nunca troca** timesyncd por chrony. `baseline-verify`: **FALHA** se não sincronizado ou sem serviço de hora |
| Atalhos de terminal (alias) para TODOS os usuários, inclusive root | `ATALHOS` | `r=reset` | `nome=comando`, vários separados por espaço (o comando pode ter espaços: `r=reset ll=ls -la`); nome `[a-z][a-z0-9_-]*`; proibidos no comando `; \| & \` $ ( ) < >`, barra invertida e aspas; `nenhum` remove tudo. Grava **um bloco** entre `# baseline: atalhos (início)` e `# baseline: atalhos (fim)` em `/etc/bash.bashrc`, **reescrito por inteiro** a cada execução (rodar 2× não duplica). Nunca edita `~/.bashrc` de usuário. Só vale em shells interativos do bash. `baseline-verify`: o bloco bate com o `.env` e `bash -ic 'alias r'` responde como root e como o administrador |
| Anexar ao Ubuntu Pro (Livepatch, ESM)? | `PRO_ANEXAR` | `nao` | token de https://ubuntu.com/pro digitado **sem eco**, passado ao `pro attach --attach-config` por **arquivo temporário 0600** (pasta 0700, apagado no fim e no `trap`); **nunca** em argumento, log, resumo nem `baseline.env` (o resumo só diz "anexar: sim"). Já anexado: pula. `baseline-verify`: informa o estado (`pro status --format json`) e dá AVISO só se o `.env` pediu e não está anexado |

## Listas de IPs/redes

Gestão do SSH e origens do SNMP são perguntadas **um item por vez**: digite um IP (`a.b.c.d`) ou uma rede
(`a.b.c.0/24`) e Enter; repita para o próximo; **Enter vazio conclui**. Também aceita vários de uma vez,
separados por espaço ou vírgula. `limpar` recomeça a lista. Endereços de exemplo/documentação são recusados.

## Vários servidores

O `/root/baseline.env` de um servidor pronto serve de modelo para o próximo: copie, troque `HOSTNAME_` e `V6`,
e rode `sudo bash baseline.sh --respostas respostas.env`. O que estiver no arquivo não é perguntado; o que
faltar, é. Senhas do SNMP nunca vão para arquivo. Veja `respostas.exemplo.env`.

## Rodar de novo

Pode. As respostas anteriores viram padrão (Enter mantém), as regras `# baseline:` do UFW são trocadas e as
demais ficam, o usuário SNMP só troca de senha se você pedir, e "atualizar agora" passa a ter padrão **não**
(num servidor em produção a atualização pode reiniciar serviços).

## Versão 1 (g2-baseline)

Servidores que rodaram o `g2-baseline.sh` funcionam: a v2 lê o `/root/g2-baseline.env` antigo como padrão e
substitui o `10-g2-hardening.conf` pelo `10-baseline.conf` (o antigo fica na pasta de cópias).

## Segurança

- Os arquivos de respostas são **lidos**, nunca executados (`source`).
- Senhas do SNMP: digitadas duas vezes, sem eco; o teste do `snmpget` usa um `snmp.conf` temporário 0600
  (nunca a senha em argumento, que apareceria no `ps`).
- Validação de IP/rede pelo `ipaddress` do Python; `0.0.0.0/0` não é aceito como rede de gestão.
- Se você estiver conectado de um IP fora da lista de gestão, o script avisa e oferece incluí-lo.
- **Log (`/root/baseline-<data>.log`)**: criado `600` (root) antes de gravar o primeiro byte, e o `baseline-verify` confere
  `600` no log e no `baseline.env` e `700` na pasta de cópias. **Não contém senhas** (nem as do SNMP, nem
  o que você digita: o terminal faz o eco, não o log). **Contém topologia**: IPs do servidor, do gateway, das redes de
  gestão e do monitoramento, porta do SSH, usuários (administrador, SNMP, AllowUsers), hostname, location/contact do SNMP e
  as impressões digitais das chaves (o comentário `usuario@notebook` da chave **não** é gravado). Trate o log como reservado:
  não o anexe a chamados nem o envie sem revisar. Valores inválidos vindos de `--respostas` aparecem truncados em 40 caracteres.
- A chave efêmera do autoteste e o `snmp.conf` temporário (com as senhas, só durante o teste) ficam em pastas `0700` e são
  apagados na saída do script, mesmo se ele for interrompido (`trap`); o `baseline-verify` acusa uma chave
  `baseline-selftest-*` esquecida no `authorized_keys`.

## Testes

```bash
bash tests/run.sh       # unitários + política + sshd real (a parte do sshd roda com sudo; no CI é obrigatória)
shellcheck -S warning *.sh tests/*.sh
```

A parte de integração sobe um `sshd` de verdade numa porta alta e prova: o `10-baseline.conf` passa no `sshd -t`, o efetivo
bate, o autoteste passa e falha quando deve, `AllowTcpForwarding no` nega `ssh -R`, e o `Accepted publickey` do loopback não
vale como prova do OK. O CI (`.github/workflows/verificar.yml`) roda tudo a cada PR.

## Contrato do baseline.env

`/root/baseline.env` (modo `600`, dono root) é a **interface estável** com outros produtos (ex.: o DNS Admin lê estas chaves para
não perguntar de novo). Formato: uma `CHAVE="valor"` por linha, **sem senha nem token**, listas separadas por espaço, vazio = não configurado.
**Leia o arquivo, nunca faça `source`** dele. Chaves ausentes significam um baseline mais antigo — confira `BASELINE_VERSAO` e trate a falta.

| Chave | Conteúdo | Exemplo | Desde |
|---|---|---|---|
| `BASELINE_VERSAO` | versão do baseline que gravou o arquivo | `2.2.0` | 2.0.0 |
| `ADMIN_USER` | usuário administrador (único com sudo/SSH garantido) | `admin` | 2.0.0 |
| `SSH_PORT` | porta do SSH | `44320` | 2.0.0 |
| `GESTAO_SSH` | IPs/redes autorizados a acessar o SSH (origens de gestão) | `192.0.2.10 198.51.100.0/24` | 2.0.0 |
| `SSH_USUARIOS` | usuários do `AllowUsers` | `admin backup` | 2.1.0 |
| `SNMP` | `sim`/`nao`: SNMPv3 configurado | `sim` | 2.0.0 |
| `SNMP_ORIGENS` | IPs/redes do monitoramento (porta 161/udp) | `192.0.2.51` | 2.0.0 |
| `SNMP_USER` | usuário SNMPv3 (as senhas nunca são gravadas) | `monitorv3` | 2.0.0 |
| `SNMP_LOCATION` | `sysLocation` | `Sala_Servidores` | 2.0.0 |
| `SNMP_CONTACT` | `sysContact` | `suporte@exemplo.com.br` | 2.0.0 |

Os nomes acima são **os do script** (`SSH_PORT` e `GESTAO_SSH`, não `SSH_PORTA`/`SSH_ORIGENS`). As demais chaves do arquivo
(`TZ_`, `V6`, `ATALHOS`…) são estado interno do baseline: podem mudar sem aviso.

**Renomear, remover ou mudar o formato de uma chave do contrato exige um aviso no [CHANGELOG](CHANGELOG.md)** (seção
"Contrato do baseline.env") **na mesma versão**. `tests/run.sh` reprova se o README deixar de documentar uma chave do contrato
ou se o `salvar_env` deixar de gravá-la.

## Versões

Cada versão é uma tag (`vX.Y.Z`) com `SHA256SUMS` e o texto da release em `docs/`; o histórico está no [CHANGELOG](CHANGELOG.md). Mudou um script? Regenere
`sha256sum baseline.sh baseline-verify.sh > SHA256SUMS` (o teste reprova se estiver desatualizado).
