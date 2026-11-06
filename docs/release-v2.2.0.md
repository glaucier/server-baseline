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
6. `sudo baseline-verify`: tudo OK; `ls -l /root/baseline-*.log` com `600`.

## Verificação (SHA-256)

```
66cbf1890225aacd6c07073c5d7d10d4dc04e17375703d688754f74fa7dab1fc  baseline.sh
1b21113703f47d886bf45e8d73b734e187689d12061a6d40e6d7b9f1d2cbb82a  baseline-verify.sh
```

```bash
cd /tmp
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/baseline.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/baseline-verify.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.0/SHA256SUMS
sha256sum -c SHA256SUMS
```

Mudanças em relação à v2.1.0: https://github.com/glaucier/server-baseline/compare/v2.1.0...v2.2.0
