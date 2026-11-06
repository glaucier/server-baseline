# v2.2.1 — a volta automática não mexe em arquivo de outro produto

> **Rascunho. Publique a release (tag `v2.2.1`) depois do merge e do teste na VM.** Contém tudo da v2.2.0 (disco, relógio, atalhos, Ubuntu Pro e a detecção de conflito de SSH com outro produto); veja o [CHANGELOG](../CHANGELOG.md).

## Correção

O `volta.sh` (volta automática de 5 min, ou manual pelo console) restaura agora **só o que o próprio baseline grava**:

- **SSH:** apaga o `10-baseline.conf` novo e devolve o de antes, se havia, e o arquivo da v1 que o baseline moveu. **Nunca** copia o diretório `sshd_config.d` de volta: um `01-outro.conf` (ex.: do DNS Admin) alterado, criado ou removido dentro da janela continua como estava.
- **UFW:** apaga as regras marcadas `# baseline:`, recoloca as de antes, devolve as políticas padrão e ativo/inativo. Regras de outros produtos ficam como estão. **Não** copia mais o `/etc/ufw` inteiro.
- **SNMP:** restaura o `snmpd.conf` do backup **somente se** o que está lá foi gerado pelo baseline.

Sem mudança de chaves do `baseline.env` nem de perguntas.

## Checklist do teste na VM

1. Rodar o baseline com o `01-dns-admin.conf` presente; **antes do OK**, alterar o `01-dns-admin.conf` (ex.: trocar um valor) e criar uma regra UFW de outro produto (`sudo ufw allow 8080/tcp comment teste-outro`).
2. Responder `NAO` (ou deixar vencer os 5 min): SSH/UFW voltam; conferir que `01-dns-admin.conf` **mantém a alteração** e a regra `8080/tcp` continua em `ufw status`, e que as regras `baseline:` sumiram (ou voltaram às de antes).
3. `sudo baseline-verify` e `ls /root/baseline-backup-*/PENDENTE` (não deve existir).

## Verificação (SHA-256)

```
b90041d790040d8b18704bb010629780c25db55a24238cc501e88123d961104e  baseline.sh
748909fd445a38b7a5799ddccdbbca1bdf935d8b1281e5763720d567f4eae220  baseline-verify.sh
```

```bash
cd /tmp
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.1/baseline.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.1/baseline-verify.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.1/SHA256SUMS
sha256sum -c SHA256SUMS
```

Mudanças em relação à v2.2.0: https://github.com/glaucier/server-baseline/compare/v2.2.0...v2.2.1
