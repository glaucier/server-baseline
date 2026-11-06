# CHANGELOG

Formato: versão, data, o que mudou. Mudanças nas chaves do `/root/baseline.env` que outros produtos leem (ver
"Contrato do baseline.env" no README) aparecem sempre na subseção **Contrato do baseline.env**: **renomear, remover ou
mudar o formato de uma chave do contrato exige aviso aqui, na mesma versão.**

## 2.2.0 — 2026-11-06

Achados da simulação "como cliente" do DNS Admin (VM Ubuntu 24.04 limpa).

### Novo
- **Disco (LVM):** se a raiz está num LV e o VG tem > 1 GB livre, pergunta "Usar todo o disco para o sistema?" (padrão sim) e aplica `lvextend -r -l +100%FREE`. `baseline-verify`: AVISO se sobrar > 1 GB livre no VG da raiz.
- **Relógio:** confere `NTPSynchronized` e o serviço de hora (timesyncd ou chrony); espera até 60 s; AVISO no resumo se persistir; FALHA no `baseline-verify`. Não troca de serviço.
- **Atalhos de terminal:** `ATALHOS` (padrão `r=reset`), um bloco marcado em `/etc/bash.bashrc`, reescrito por inteiro, idempotente; nunca toca `~/.bashrc`. `baseline-verify` confere o bloco e `bash -ic 'alias …'` como root e como o administrador.
- **Ubuntu Pro (opcional):** `PRO_ANEXAR` (padrão nao); token sem eco, por arquivo temporário 0600, nunca em argv/log/`.env`/resumo.
- `docs/release-v2.2.0.md`, README com tabelas das perguntas e a seção "Contrato do baseline.env".

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
