# CHANGELOG

Formato: versão, data, o que mudou. Mudanças nas chaves do `/root/baseline.env` que outros produtos leem (ver
"Contrato do baseline.env" no README) aparecem sempre na subseção **Contrato do baseline.env**: **renomear, remover ou
mudar o formato de uma chave do contrato exige aviso aqui, na mesma versão.**

## 2.2.1 — 2026-11-06

### Corrigido
- **`volta.sh` restaura SÓ o que o próprio baseline grava.** Antes ele copiava de volta o diretório `sshd_config.d` e o `/etc/ufw` inteiros: um arquivo/regra de outro produto alterado (ou removido) dentro da janela de 5 min seria revertido (ou ressuscitado). Agora:
  - SSH: apaga o `10-baseline.conf` novo e devolve o de antes (se havia) e o arquivo da v1 que o baseline moveu; nunca toca em outros arquivos de `sshd_config.d`;
  - UFW: apaga as regras marcadas `# baseline:`, recoloca as de antes (lidas do `ufw status` antes de mexer, só no formato exato do baseline), devolve as políticas padrão e ativo/inativo; regras de outros produtos ficam como estão;
  - SNMP: restaura o `snmpd.conf` do backup **só se** o que está lá foi gerado pelo baseline.
- `tests/volta.sh` (36 verificações): um `01-outro.conf` alterado dentro da janela continua como estava depois da volta; arquivo criado/removido por outro produto idem; regras UFW de outros produtos idem.

### Contrato do baseline.env
- Nenhuma chave alterada.

## 2.2.0 — 2026-11-06

Achados da simulação "como cliente" do DNS Admin (VM Ubuntu 24.04 limpa).

### Novo
- **Disco (LVM):** se a raiz está num LV e o VG tem > 1 GB livre, pergunta "Usar todo o disco para o sistema?" (padrão sim) e aplica `lvextend -r -l +100%FREE`. `baseline-verify`: AVISO se sobrar > 1 GB livre no VG da raiz.
- **Relógio:** confere `NTPSynchronized` e o serviço de hora (timesyncd ou chrony); espera até 60 s; AVISO no resumo se persistir; FALHA no `baseline-verify`. Não troca de serviço.
- **Atalhos de terminal:** `ATALHOS` (padrão `r=reset`), um bloco marcado em `/etc/bash.bashrc`, reescrito por inteiro, idempotente; nunca toca `~/.bashrc`. `baseline-verify` confere o bloco e `bash -ic 'alias …'` como root e como o administrador.
- **Ubuntu Pro (opcional):** `PRO_ANEXAR` (padrão nao); token sem eco, por arquivo temporário 0600, nunca em argv/log/`.env`/resumo.
- `docs/release-v2.2.0.md`, README com tabelas das perguntas e a seção "Contrato do baseline.env".

### Corrigido (teste real na VM, 06/11 13:46)
- O autoteste abortava e restaurava SSH/UFW quando outro produto (`01-dns-admin.conf`: `ClientAliveInterval 3`, `ClientAliveCountMax 15`) ordenava **antes** do `10-baseline.conf` e vencia (o sshd usa a 1.ª ocorrência), e o problema só aparecia **depois** de aplicar.
  Agora o baseline detecta isso **antes do resumo** (simulação com `sshd -T -f`): conforto vencido → aviso no resumo e o autoteste espera o valor que vence; segurança com valor menos seguro (Port, PasswordAuthentication, PermitRootLogin, PubkeyAuthentication, AllowUsers…) → **para antes de aplicar**, citando o arquivo; diferença inesperada continua abortando. Nunca edita nem move arquivo de outro produto.
  `baseline-verify`: mesma regra (conforto = AVISO "outro arquivo vence", segurança = FALHA citando o arquivo).

### Corrigido (2.º teste real na VM, 06/11 14:38–14:43)
- **Falso conflito de porta:** `Port 44320` repetida em outro arquivo com o mesmo valor do baseline fazia o resumo parar ("escutaria em: 44320 44320 … Port ACUMULA"). Agora compara o **conjunto** de portas efetivo (sem repetição): só é conflito com porta **a mais** ou se faltar a escolhida (`baseline.sh` e `baseline-verify`).
- **Verify antigo depois de abortar:** toda mensagem "Abortado" diz `Para conferir com a versão nova: sudo bash <pasta do script>/baseline-verify.sh`; o `baseline-verify` imprime a **própria versão** no cabeçalho (além da versão que aplicou o padrão).
- **SNMP com arquivo de outro produto:** o baseline **não sobrescreve** um `snmpd.conf` que não seja seu nem o de fábrica do pacote (aviso no resumo "mantido; só o usuário SNMPv3 é conferido", sem pedir senhas). No `baseline-verify`, escutar em `0.0.0.0:161`/`[::]:161` cobre os endereços esperados, e para `snmpd.conf` de outro produto endereço/localização/contato viram AVISO informativo (`rouser`, "sem community" e o usuário SNMPv3 continuam FALHA).
- **Teste real do SNMP no verify:** cada senha em linha própria com `(digitado: N caracteres)`; testa em `127.0.0.1` **e** no IP ("responde local, não no IP — confira o agentAddress e o UFW"); mostra o **motivo** da falha sem senhas (`Timeout`, `Authentication failure`/`wrong digest`, `Decryption error`, `Unknown user name`); senhas só em `snmp.conf` 0600 apagado no `trap`, nunca no argv.

### Contrato do baseline.env
- Nenhuma chave existente foi renomeada, removida nem mudou de formato.
- Chaves **novas** (não fazem parte do contrato; são estado interno): `DISCO_EXPANDIR`, `ATALHOS`, `PRO_ANEXAR`.
- O contrato passa a ser documentado: `BASELINE_VERSAO`, `ADMIN_USER`, `SSH_PORT`, `GESTAO_SSH`, `SSH_USUARIOS`, `SNMP`, `SNMP_ORIGENS`, `SNMP_USER`, `SNMP_LOCATION`, `SNMP_CONTACT`.

## 2.1.0 — 2026-11-05
- SSH: `AllowUsers` (`SSH_USUARIOS`), `AllowTcpForwarding no`, `AllowAgentForwarding no`, `LoginGraceTime`, `ClientAliveInterval`, `ClientAliveCountMax`.
- Autoteste (login real do administrador pelo loopback) antes do OK; OK com prova no journal e segundo OK; marcador `PENDENTE` quando um reboot desarma a volta automática.
- `baseline-verify`: itens novos pelo `sshd -T -C`; permissões do log/`baseline.env`/cópias.
- Log criado 600; comentário da chave fora do log; temporários apagados no `trap`.
- Testes (`tests/run.sh`, com `sshd` real) e CI; `SHA256SUMS`.

### Contrato do baseline.env
- Nova chave `SSH_USUARIOS`. Nenhuma renomeada ou removida.

## 2.0.0
- Reescrita genérica e interativa (v1 era `g2-baseline`): chaves do `baseline.env` como no contrato do README; lê o `g2-baseline.env` antigo como padrão.
