# v2.2.0 — disco, relógio, atalhos de terminal e Ubuntu Pro

> **Rascunho. Só publique a release (e crie a tag `v2.2.0`) depois do merge e do teste na VM** (checklist abaixo).
> Tag no commit do merge em `main`; Releases → Draft a new release.

Achados da simulação "como cliente" do DNS Admin (06/11/2026, VM Ubuntu 24.04 limpa).

## Novidades

Cada item é uma pergunta/etapa com explicação, exemplo e padrão, aparece no **RESUMO** antes de "Aplicar?" e é conferido pelo `baseline-verify`.

- **Disco (LVM).** O instalador deixa o LV da raiz menor que o disco. Havendo **> 1 GB livre** no VG da raiz, pergunta "Usar todo o disco para o sistema?" (padrão **sim**) e aplica `lvextend -r -l +100%FREE <LV da raiz>` (LV descoberto por `findmnt`). Sem LVM ou sem espaço livre: nada, sem pergunta. `baseline-verify`: **AVISO** se sobrar > 1 GB livre no VG da raiz. Chave: `DISCO_EXPANDIR`.
- **Relógio.** Confere `NTPSynchronized=yes` e o serviço de hora ativo (systemd-timesyncd **ou** chrony — **nunca troca um pelo outro**). Não sincronizado: espera até 60 s; persistindo, **AVISO** no resumo ("DNSSEC e certificados dependem da hora certa"). `baseline-verify`: **FALHA**.
- **Atalhos de terminal (alias)** para todos os usuários, inclusive root. Padrão `r=reset`; aceita `nome=comando nome2=comando com espaços` (nome `[a-z][a-z0-9_-]*`; proibidos `; | & ` $ ( ) < >`, \\ e aspas; `nenhum` remove). **Um bloco** entre `# baseline: atalhos (início)` e `(fim)` em `/etc/bash.bashrc`, reescrito por inteiro a cada execução (**rodar 2× não duplica**). Nunca edita `~/.bashrc` de usuário. Chave: `ATALHOS`. `baseline-verify`: o bloco bate com o `.env` e `bash -ic 'alias r'` responde como root e como o administrador.
- **Ubuntu Pro / Livepatch (opcional, padrão não).** Token de https://ubuntu.com/pro lido **sem eco**, passado ao `pro attach --attach-config` por **arquivo temporário 0600** apagado no fim e no `trap`; **nunca** em argv, log, `.env` ou resumo (só "anexar: sim"). Já anexado: pula. Chave: `PRO_ANEXAR`. `baseline-verify`: informa o estado (`pro status --format json`); AVISO só se o `.env` pediu e não está anexado.
- **Conflito de SSH com outro produto (corrigido antes da tag).** Se um arquivo de `sshd_config.d` que ordena **antes** do `10-baseline.conf` (ex.: `01-dns-admin.conf`) define a mesma diretiva, o sshd usa a **1.ª ocorrência** e ele vence. Antes do resumo o baseline simula o sshd e: **conforto** (`ClientAlive*`, `LoginGraceTime`) → aviso no resumo (`SSH ClientAliveInterval: escolhido 300, mas 01-dns-admin.conf define 3 e VENCE (o sshd usa a 1.ª ocorrência)`) e o autoteste espera o valor que vence; **segurança** com valor menos seguro (`Port`, `PasswordAuthentication`, `PermitRootLogin`, `PubkeyAuthentication`, `AllowUsers`…) → **para antes de aplicar**, citando o arquivo; diferença inesperada continua abortando e restaurando. Nunca edita nem move arquivo de outro produto. `baseline-verify`: conforto = AVISO "outro arquivo vence", segurança = FALHA.
- **Correções do 2.º teste real na VM (06/11 14:38–14:43).** (1) `Port` repetida em outro arquivo com o **mesmo valor** do baseline não é conflito (compara o conjunto de portas efetivo, sem repetição; só porta a mais ou faltando para). (2) Toda mensagem "Abortado" aponta `sudo bash <pasta do script>/baseline-verify.sh` (o instalado só é atualizado no fim) e o `baseline-verify` imprime a **própria versão** no cabeçalho. (3) **`snmpd.conf` de outro produto** (ex.: DNS Admin, `agentAddress udp:161,udp6:161`): o baseline **não o sobrescreve** (aviso no resumo, sem pedir senhas); no verify, `0.0.0.0:161`/`[::]:161` cobrem os endereços, e endereço/localização/contato de arquivo alheio viram AVISO informativo (`rouser`, "sem community" e o usuário SNMPv3 seguem FALHA). (4) **Teste real do SNMP** no verify: senhas em linhas próprias com `(digitado: N caracteres)`, teste em `127.0.0.1` e no IP, **motivo** da falha sem senhas (`Timeout`, `Authentication failure`/`wrong digest`, `Decryption error`, `Unknown user name`), senhas só em `snmp.conf` 0600 apagado no `trap`.
- **Contrato do baseline.env** documentado no README: `BASELINE_VERSAO`, `ADMIN_USER`, `SSH_PORT`, `GESTAO_SSH`, `SSH_USUARIOS`, `SNMP`, `SNMP_ORIGENS`, `SNMP_USER`, `SNMP_LOCATION`, `SNMP_CONTACT`. Renomear/remover/mudar formato de uma delas exige aviso no [CHANGELOG](../CHANGELOG.md) (novo).

## Compatibilidade

- Nenhuma chave existente do `baseline.env` foi renomeada ou removida; entram `DISCO_EXPANDIR`, `ATALHOS`, `PRO_ANEXAR`.
- `baseline-verify` com um `.env` da 2.0/2.1: itens novos viram **AVISO**, não FALHA, até rodar o baseline de novo.
- O token do Ubuntu Pro não é chave de arquivo de respostas: é sempre digitado.

## Checklist do teste na VM (antes de publicar)

1. VM 24.04 com LVM e disco maior que o LV: a pergunta do disco aparece com os GB certos; `df -h /` cresce após aplicar; rodar de novo **não** pergunta.
2. VM sem espaço livre no VG / sem LVM: nenhuma pergunta de disco.
3. Relógio: `timedatectl` sincronizado → sem aviso; com a rede UDP 123 bloqueada → espera 60 s e mostra o AVISO no resumo; `baseline-verify` dá FALHA.
4. Atalhos: `r` funciona em shell novo de root e do administrador; rodar o baseline 2× deixa **um** bloco; responder `nenhum` remove o bloco.
5. Ubuntu Pro com token de teste: `pro status` anexado, `grep -R <token> /root` **sem resultado** (log, `.env`, cópias) e `ps` sem o token durante o attach.
6. **Com o `01-dns-admin.conf` do DNS Admin presente** (`ClientAliveInterval 3` / `ClientAliveCountMax 15`): o resumo mostra os dois avisos "escolhido … mas 01-dns-admin.conf define … e VENCE", o autoteste **passa**, o OK é aceito e o `baseline-verify` mostra AVISO "outro arquivo vence" (sem FALHA). Com `PasswordAuthentication yes` num `01-teste.conf`: para **antes** de aplicar, citando o arquivo.
7. **Com o `snmpd.conf` do DNS Admin** (`agentAddress udp:161,udp6:161`): o resumo mostra "snmpd.conf de outro produto — mantido; só o usuário SNMPv3 é conferido" e o arquivo **não muda** (`md5sum` igual antes/depois); `sudo baseline-verify` mostra "snmpd escuta em todos os endereços — inclui …" e "snmpd.conf é de outro produto"; no teste real do SNMP (senhas digitadas) cada pergunta fica em linha própria com "(digitado: N caracteres)" e, com senha errada, o motivo aparece sem as senhas (confirme com `ps` durante o teste: as senhas não aparecem).
8. **Com `Port 44320` num `01-dns-admin.conf`** e o baseline em 44320: segue **sem** parar; com `Port 2222` no mesmo arquivo: para citando o arquivo. Se algo abortar, a última linha diz como rodar o verify novo.
9. `sudo baseline-verify`: tudo OK; `ls -l /root/baseline-*.log` com `600`.

## Verificação (SHA-256)

```
55bbe6f5d785cf072f84ecd6de2315151cb06c33fc76bead7550fb24285fd950  baseline.sh
824464436f8a3a40e8b0efffb9a01d96d8d8e0998dd799f2b50f72d0864a07be  baseline-verify.sh
```

```bash
cd /tmp
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/baseline.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/baseline-verify.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/SHA256SUMS
sha256sum -c SHA256SUMS
```

Mudanças em relação à v2.1.0: https://github.com/glaucier/server-baseline/compare/v2.1.0...v2.2.0
