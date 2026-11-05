#!/usr/bin/env bash
# Integração com um sshd REAL (Ubuntu 24.04): sobe um sshd numa porta alta com o 10-baseline.conf gerado pelo baseline e prova
#  - sshd -t aceita o arquivo e o sshd -T efetivo bate (sshd_diverge);
#  - o autoteste (login real do admin, chave efêmera, loopback) passa e deixa o authorized_keys limpo;
#  - AllowUsers/Match que barra o admin → o autoteste FALHA (volta automática);
#  - AllowTcpForwarding no realmente nega ssh -R;
#  - o "Accepted publickey" do loopback aparece no log do sshd (LogLevel padrão INFO) e NÃO conta como prova do OK.
# Precisa de root. Cria o usuário temporário bltest e limpa tudo no fim.
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "integracao.sh exige root"; exit 1; }
RAIZ=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d); chmod 755 "$TMP"
PORTA=${PORTA_TESTE:-22222}
USR=bltest
SSHD_PID=""
limpa() { [[ -n "$SSHD_PID" ]] && kill "$SSHD_PID" 2>/dev/null; userdel -r "$USR" >/dev/null 2>&1; rm -rf "$TMP"; }
trap limpa EXIT
FALHAS=0; N=0
t() { local d=$1; shift; N=$((N+1)); if "$@" >"$TMP/saida" 2>&1; then echo "    ok    $d"; else echo "    FALHA $d"; sed 's/^/          | /' "$TMP/saida"; FALHAS=$((FALHAS+1)); fi; }

install -d -m 0755 /run/sshd
id "$USR" >/dev/null 2>&1 || useradd -m -s /bin/bash -p '*' "$USR"
H=$(getent passwd "$USR" | cut -d: -f6); AK="$H/.ssh/authorized_keys"
install -d -m 700 -o "$USR" -g "$USR" "$H/.ssh"
ssh-keygen -q -t ed25519 -N '' -C "operador@notebook" -f "$TMP/operador"
printf '%s' "$(cat "$TMP/operador.pub")" > "$AK"        # SEM quebra de linha final, de propósito
chown "$USR:$USR" "$AK"; chmod 600 "$AK"
ssh-keygen -q -t ed25519 -N '' -f "$TMP/hostkey"

# variáveis que o baseline usa
# shellcheck disable=SC1091
source "$RAIZ/baseline.sh"
ADMIN_USER=$USR; SSH_PORT=$PORTA; SSH_USUARIOS=$USR; SSH_TCP_FWD=nao; SSH_AGENT_FWD=nao; SSH_GRACE=30; SSH_ALIVE_INT=300; SSH_ALIVE_MAX=2; TS=integ

monta_sshd() { # $1 = linhas extras (ex.: AllowGroups)
  mkdir -p "$TMP/conf.d"; rm -f "$TMP"/conf.d/*
  gerar_sshd_conf > "$TMP/conf.d/10-baseline.conf"
  [[ -n "${1:-}" ]] && printf '%s\n' "$1" > "$TMP/conf.d/20-extra.conf"
  printf 'HostKey %s\nListenAddress 127.0.0.1\nUsePAM no\nPidFile %s\nSubsystem sftp internal-sftp\nInclude %s/conf.d/*.conf\n' \
    "$TMP/hostkey" "$TMP/sshd.pid" "$TMP" > "$TMP/sshd_config"
}
sobe_sshd() {
  [[ -n "$SSHD_PID" ]] && { kill "$SSHD_PID" 2>/dev/null; wait "$SSHD_PID" 2>/dev/null; }
  : > "$TMP/sshd.log"
  /usr/sbin/sshd -D -e -f "$TMP/sshd_config" 2> "$TMP/sshd.log" & SSHD_PID=$!
  local _; for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORTA") 2>/dev/null && return 0; sleep 0.2; done
  cat "$TMP/sshd.log"; return 1
}
# o autoteste lê as host keys de /etc/ssh; aqui a do sshd de teste vai para um espelho via a função, então usamos a chave de teste
autoteste_com_hostkey_de_teste() {
  # redireciona o glob de host keys do autoteste para a chave de teste (cópia do .pub com o nome esperado)
  mkdir -p "$TMP/etc_ssh"; cp "$TMP/hostkey.pub" "$TMP/etc_ssh/ssh_host_ed25519_key.pub"
  sed "s#/etc/ssh/ssh_host_#$TMP/etc_ssh/ssh_host_#" "$RAIZ/baseline.sh" > "$TMP/baseline_teste.sh"
  ( source "$TMP/baseline_teste.sh"; ADMIN_USER=$USR; SSH_PORT=$PORTA; SSH_USUARIOS=${SU:-$USR}; SSH_TCP_FWD=nao; SSH_AGENT_FWD=nao; SSH_GRACE=30
    SSH_ALIVE_INT=300; SSH_ALIVE_MAX=2; TS=integ; H=$H; AK=$AK
    # sshd -T do sistema não conhece o sshd de teste: aponta para o arquivo de teste
    sshd() { /usr/sbin/sshd -f "$TMP/sshd_config" "$@"; }
    autoteste_ssh )
}

deve_falhar() { ! "$@"; }
cria_helper_motivo() { # script que roda o autoteste e imprime o que ele diz
  { echo '#!/usr/bin/env bash'; declare -f autoteste_com_hostkey_de_teste
    echo "TMP='$TMP' RAIZ='$RAIZ' USR='$USR' PORTA='$PORTA' H='$H' AK='$AK'"
    echo 'autoteste_com_hostkey_de_teste 2>&1; true'; } > "$TMP/motivo_login.sh"; chmod +x "$TMP/motivo_login.sh"
}

echo "  -- configuração padrão"
monta_sshd ""
t "sshd -t aceita o 10-baseline.conf gerado" /usr/sbin/sshd -t -f "$TMP/sshd_config"
sobe_sshd || { echo "sshd de teste não subiu"; exit 1; }
t "sshd -T -C efetivo bate com o escolhido (sshd_diverge)" bash -c '/usr/sbin/sshd -T -f "$1" -C user=bltest,host=localhost,addr=127.0.0.1 | { source "$2"; ADMIN_USER=bltest; SSH_PORT='"$PORTA"'; SSH_USUARIOS=bltest; SSH_TCP_FWD=nao; SSH_AGENT_FWD=nao; SSH_GRACE=30; SSH_ALIVE_INT=300; SSH_ALIVE_MAX=2; sshd_diverge; }' _ "$TMP/sshd_config" "$RAIZ/baseline.sh"
t "autoteste: login real do admin passa" autoteste_com_hostkey_de_teste
t "autoteste: authorized_keys sem a chave efêmera" bash -c '! grep -q baseline-selftest "$1"' _ "$AK"
t "autoteste: a chave do operador continua íntegra (não colou na linha)" bash -c 'ssh-keygen -lf "$1" | grep -c ED25519 | grep -qx 1' _ "$AK"
t "autoteste: sem diretório temporário de chave sobrando" bash -c '! ls /tmp/tmp.*/k 2>/dev/null | grep -q .'

echo "  -- AllowTcpForwarding no nega de verdade"
t "controle: o mesmo login do operador, sem -R, funciona" timeout 20 ssh -F /dev/null -p "$PORTA" -i "$TMP/operador" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR bltest@127.0.0.1 true
t "ssh -R é negado (ExitOnForwardFailure)" bash -c '! timeout 20 ssh -F /dev/null -p "$1" -i "$2" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes -o LogLevel=ERROR -R 0:127.0.0.1:22 bltest@127.0.0.1 true' _ "$PORTA" "$TMP/operador"

echo "  -- prova do login no log do sshd (LogLevel padrão INFO)"
t "login do operador pelo loopback foi registrado como 'Accepted publickey'" grep -q "Accepted publickey for $USR from 127.0.0.1 " "$TMP/sshd.log"
mkdir -p "$TMP/bin"; printf '#!/usr/bin/env bash\ncat "%s"\n' "$TMP/sshd.log" > "$TMP/bin/journalctl"; chmod +x "$TMP/bin/journalctl"
t "esse login (e o do autoteste) NÃO conta como prova do OK" env PATH="$TMP/bin:$PATH" bash -c 'source "$1"; ADMIN_USER=bltest; ! login_remoto_visto 1' _ "$RAIZ/baseline.sh"
echo "Accepted publickey for $USR from 203.0.113.9 port 51234 ssh2: ED25519 SHA256:x" >> "$TMP/sshd.log"
t "um login do mesmo formato vindo de IP externo conta" env PATH="$TMP/bin:$PATH" bash -c 'source "$1"; ADMIN_USER=bltest; login_remoto_visto 1 && [[ $LOGIN_IP == 203.0.113.9 ]]' _ "$RAIZ/baseline.sh"

echo "  -- regra que barra o admin (AllowGroups em outro arquivo) → autoteste falha"
monta_sshd "AllowGroups grupo-que-nao-existe"
sobe_sshd || { echo "sshd de teste não subiu"; exit 1; }
t "sshd -t não vê problema (por isso o login real é necessário)" /usr/sbin/sshd -t -f "$TMP/sshd_config"
cria_helper_motivo
t "autoteste detecta o bloqueio (login real recusado)" deve_falhar autoteste_com_hostkey_de_teste
t "...e o motivo é o login recusado (não outro erro)" bash -c 'out=$("$1"); [[ "$out" == *"foi recusado com as regras novas"* ]]' _ "$TMP/motivo_login.sh"
t "e mesmo no fracasso a chave efêmera é removida" bash -c '! grep -q baseline-selftest "$1"' _ "$AK"

echo "  -- AllowUsers efetivo diferente do escolhido → camada 1 falha"
monta_sshd "AllowUsers intruso"
sobe_sshd || { echo "sshd de teste não subiu"; exit 1; }
t "AllowUsers acumulado em outro arquivo é detectado" deve_falhar autoteste_com_hostkey_de_teste
t "...e o motivo é a divergência de AllowUsers (camada 1)" bash -c 'out=$("$1"); [[ "$out" == *"diverge do escolhido"* && "$out" == *"intruso"* ]]' _ "$TMP/motivo_login.sh"

echo
(( FALHAS )) && { echo "    integração: $FALHAS de $N falharam"; exit 1; }
echo "    integração: $N verificações passaram"
