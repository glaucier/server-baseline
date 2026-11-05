# v2.1.0 — endurecimento do SSH, autoteste e confirmação com prova

Texto para a página da release `v2.1.0` (cole em **Releases → Draft a new release**, tag `v2.1.0`, alvo: o commit do merge em `main`).

## Novidades

**SSH (`10-baseline.conf`) — cada item é perguntado, com explicação, exemplo e padrão seguro; tudo vai para `/root/baseline.env`**

- `AllowUsers` (padrão: só o administrador; aceita lista; o administrador é obrigatório) — `SSH_USUARIOS`
- `AllowTcpForwarding no` — `SSH_TCP_FWD` · `AllowAgentForwarding no` — `SSH_AGENT_FWD`
- `LoginGraceTime 30` · `ClientAliveInterval 300` · `ClientAliveCountMax 2` — `SSH_GRACE`, `SSH_ALIVE_INT`, `SSH_ALIVE_MAX`

**Confirmação mais segura**

- **Autoteste antes do OK:** confere o `sshd -T -C` efetivo e faz um **login real** do administrador na porta nova (chave efêmera, só pelo loopback, removida em seguida). Se falhar, SSH e UFW **voltam sozinhos**, como no `sshd -t`.
- **OK com prova:** o `OK` só vale direto se o journal (`ssh.service`) mostrar um `Accepted publickey` do administrador vindo de IP **fora do loopback**; senão o script avisa e exige um **segundo `OK`**. O login do autoteste não conta.
- **Marcador `PENDENTE`:** um reboot antes do OK desarma a volta automática (o timer é temporário). O `baseline-verify` e a próxima execução avisam "baseline nunca confirmado" e mostram como desfazer (`volta.sh`). O README ganhou a seção sobre isso.

**baseline-verify** confere os itens novos pelo `sshd -T -C` efetivo (AllowUsers como conjunto exato), acusa chave de autoteste esquecida, execução pendente de confirmação e permissões do log (`600`), do `baseline.env` (`600`) e da pasta de cópias (`700`).

**Log e sigilo:** o log nasce `600` antes do primeiro byte; o comentário da chave pública deixou de ir ao log; valores inválidos de `--respostas` aparecem truncados; temporários (chave do autoteste, `snmp.conf` com senhas) são apagados num `trap`. O log **não contém senhas**, mas contém topologia — veja a seção *Segurança* do README.

**Testes e CI:** `tests/run.sh` (unitários, política e `sshd` real) e ShellCheck em todos os scripts; `SHA256SUMS` conferido pelo teste.

## Atualizando de uma versão anterior

- Rode `sudo bash baseline.sh` de novo: as respostas anteriores são o padrão; as perguntas novas aparecem com padrão seguro.
- Atenção ao `AllowUsers`: **contas de serviço que usam SSH (backup, rsync…) perdem o acesso se não forem listadas**. `AllowTcpForwarding no` quebra `ssh -L/-R`, `ssh -J` e o VS Code Remote.
- Até rodar de novo, o `baseline-verify` mostra AVISO (não FALHA) para os itens novos de um `baseline.env` da v2.0.0.

## Verificação (SHA-256)

```
2a103cec04ea865984783723797bf438439cd3f425cf4cd5f0299a764477827f  baseline.sh
a51207af686354a1f12ffd836da35e77c67810d553aabeae37b9034694e1009d  baseline-verify.sh
```

```bash
cd /tmp
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.1.0/baseline.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.1.0/baseline-verify.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.1.0/SHA256SUMS
sha256sum -c SHA256SUMS
```

Mudanças em relação à v2.0.0: https://github.com/glaucier/server-baseline/compare/v2.0.0...v2.1.0
