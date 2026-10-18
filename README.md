# server-baseline

Padrão inicial para servidores **Ubuntu 24.04 LTS** (qualquer 24.04.x): atualização, IPv6, SSH por chave,
UFW e SNMPv3, com verificação. Interativo, **sem dados fixos**: redes, chave, portas e SNMP são perguntados,
com explicação, exemplo e padrão.

Serve de base para qualquer servidor. Programas instalados depois (ex.: um resolvedor DNS) abrem as próprias
portas no UFW; o baseline só mexe nas regras marcadas `# baseline:`.

## O que ele faz

| Etapa | O que aplica |
|---|---|
| 1. Sistema | fuso horário, nome do servidor, `apt full-upgrade` (opcional), atualização automática diária **só de segurança, sem reboot automático**, no horário escolhido, com lista de pacotes que ela não toca (ex.: `unbound`) |
| 2. IPv6 | sugere o /64 sozinho (prefixo anunciado pelo roteador, ou o AAAA de um vizinho da mesma rede IPv4 — ex.: o servidor DNS configurado), confere com o bloco do provedor, sugere `<prefixo>::<último octeto>` e **testa antes do resumo**: duplicidade (DAD) e resposta do gateway. Grava `/etc/netplan/60-ipv6.yaml` e já ativa, sem reboot |
| 3. SSH + UFW | porta própria, só chave, sem root; UFW nega a entrada e libera o SSH só para as redes de gestão. **Volta automática**: se o novo acesso não for confirmado em 5 minutos, SSH e UFW voltam ao que eram |
| 4. SNMPv3 | somente leitura, `authPriv` (SHA-256/AES), sem community; porta 161 só para o monitoramento |

As respostas (sem senha) ficam em `/root/baseline.env` e viram o padrão da próxima execução.
Cópias do que foi alterado: `/root/baseline-backup-<data>/`. Log: `/root/baseline-<data>.log`.

## Antes de rodar

- Ubuntu Server 24.04 instalado com **IPv4 fixo** (endereço, gateway e DNS) e acesso à internet.
- Um usuário administrador com `sudo` (o criado na instalação).
- A sua **chave pública SSH** à mão (o login por senha será desligado).
- Para o SNMP: o IP do monitoramento, o usuário e as duas senhas que serão cadastradas nele.

## Como rodar

No servidor, baixe uma **versão marcada** (nunca a `main`), confira o SHA256 publicado na versão e execute:

```bash
cd /tmp
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.0.0/baseline.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.0.0/baseline-verify.sh
sha256sum baseline.sh baseline-verify.sh      # compare com a página da versão (Releases)
sudo bash baseline.sh
```

Sem internet no servidor: copie os dois arquivos para `/tmp` por `scp` e rode igual.

Ao final, **sem fechar a sessão**, abra uma conexão SSH nova na porta nova e digite `OK` no script.
Depois:

```bash
sudo reboot
sudo baseline-verify          # só leitura; saída 0 = tudo OK
```

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
