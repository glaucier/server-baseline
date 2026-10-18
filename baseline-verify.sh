#!/usr/bin/env bash
# =============================================================================
# baseline-verify.sh — confere o padrão aplicado pelo baseline.sh
# Uso: sudo baseline-verify        (ou sudo bash baseline-verify.sh)
# SÓ LEITURA: não altera nada. Saída 0 = tudo OK; 1 = alguma FALHA.
# Lê /root/baseline.env (respostas da última execução, sem senha) — sem executá-lo.
# =============================================================================
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Rode como root: sudo baseline-verify"; exit 1; }

ENV_FILE=/root/baseline.env
[[ -r "$ENV_FILE" ]] || { echo "Não achei $ENV_FILE — rode o baseline antes."; exit 1; }

declare -A E=()
while IFS= read -r linha || [[ -n "$linha" ]]; do
  [[ -z "$linha" || "$linha" == \#* || "$linha" != *=* ]] && continue
  k="${linha%%=*}"; v="${linha#*=}"
  [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
  [[ "$v" == \"*\" && ${#v} -ge 2 ]] && v="${v:1:${#v}-2}"
  E[$k]="$v"
done < "$ENV_FILE"
e() { echo "${E[$1]:-}"; }

PASS=0; FAIL=0; AVISO=0
chk() { # chk "descrição" comando...
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then echo -e "  \e[32m[OK]\e[0m    $d"; PASS=$((PASS+1))
  else echo -e "  \e[31m[FALHA]\e[0m $d"; FAIL=$((FAIL+1)); fi
}
avs() { # avs "descrição" comando...  (não reprova: só chama atenção)
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then echo -e "  \e[32m[OK]\e[0m    $d"; PASS=$((PASS+1))
  else echo -e "  \e[33m[AVISO]\e[0m $d"; AVISO=$((AVISO+1)); fi
}
sec() { echo -e "\n\e[36m== $* ==\e[0m"; }
igual() { [[ "$1" == "$2" ]]; }

IF=$(e IF); V4=$(e V4); V6=$(e V6); V6_GW=$(e V6_GW)
SSH_PORT=$(e SSH_PORT); ADMIN_USER=$(e ADMIN_USER); HORA=$(e HORA)
GW4=$(ip -4 route show default 2>/dev/null | awk '/default/{print $3; exit}')

echo "=============================================================="
echo " baseline-verify — $(hostname) — $(date '+%F %T')"
echo " uptime: $(uptime -p)   padrão aplicado pela v$(e BASELINE_VERSAO)"
echo "=============================================================="

sec "Sistema"
chk "Fuso horário $(e TZ_)"                          igual "$(timedatectl show -p Timezone --value)" "$(e TZ_)"
chk "Nome do servidor $(e HOSTNAME_)"                igual "$(hostname)" "$(e HOSTNAME_)"
chk "unattended-upgrades instalado"                   dpkg -s unattended-upgrades
chk "Atualização automática às $HORA"                 grep -q "OnCalendar=\*-\*-\* $HORA" /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf
chk "Timer apt-daily-upgrade ativo"                   systemctl is-active --quiet apt-daily-upgrade.timer
chk "Sem reboot automático"                           grep -q 'Automatic-Reboot "false"' /etc/apt/apt.conf.d/52baseline
for pk in $(e ATUALIZA_SEGURAR); do
  chk "$pk fora da atualização automática"            grep -q "\"$pk\";" /etc/apt/apt.conf.d/52baseline
done
avs "Sem reinício pendente"                           test ! -f /var/run/reboot-required

sec "Rede"
chk "IPv4 $V4 em $IF"                                 bash -c "ip -4 addr show dev '$IF' | grep -q ' $V4/'"
chk "Ping gateway IPv4 ${GW4:-?}"                     ping -c2 -W2 "${GW4:-127.0.0.255}"
chk "Resolução de DNS (getent)"                       getent hosts ubuntu.com
if [[ -n "$V6" ]]; then
  chk "IPv6 $V6/64 em $IF"                            bash -c "ip -6 addr show dev '$IF' | grep -qi ' $V6/64'"
  chk "IPv6 sem conflito (DAD)"                       bash -c "! ip -6 addr show dev '$IF' | grep -i ' $V6/64' | grep -q dadfailed"
  chk "Ping gateway IPv6 $V6_GW"                      ping -6 -c3 -W2 "$V6_GW"
  avs "Saída IPv6 para a internet (ubuntu.com)"       ping -6 -c2 -W3 ubuntu.com
fi

sec "SSH"
chk "sshd escutando na $SSH_PORT"                     bash -c "ss -tlnH 'sport = :$SSH_PORT' | grep -q ."
chk "Nada escutando na porta 22"                      bash -c "! ss -tlnH 'sport = :22' | grep -q ."
chk "ssh.service ativo e habilitado"                  bash -c "systemctl is-active --quiet ssh.service && systemctl is-enabled --quiet ssh.service"
chk "ssh.socket desativado"                           bash -c "! systemctl is-enabled --quiet ssh.socket"
SSHD_T=$(sshd -T 2>/dev/null)
for par in "port $SSH_PORT" "permitrootlogin no" "passwordauthentication no" "kbdinteractiveauthentication no" "pubkeyauthentication yes"; do
  chk "sshd efetivo: $par"                            grep -qx "$par" <<<"$SSHD_T"
done
HOME_ADM=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
AK_FPS=$(ssh-keygen -lf "$HOME_ADM/.ssh/authorized_keys" 2>/dev/null)
for fp in $(e PUBKEY_FPS); do
  chk "Chave $fp autorizada para $ADMIN_USER"        grep -qF "$fp" <<<"$AK_FPS"
done
avs "$ADMIN_USER no grupo sudo"                       bash -c "id -nG '$ADMIN_USER' | grep -qw sudo"

sec "Firewall UFW"
UFW_S=$(ufw status verbose 2>/dev/null)
chk "UFW ativo"                                       grep -q "Status: active" <<<"$UFW_S"
chk "Entrada negada por padrão"                       grep -q "deny (incoming)" <<<"$UFW_S"
chk "UFW habilitado no boot"                          systemctl is-enabled --quiet ufw
for r in $(e GESTAO_SSH); do
  chk "SSH $SSH_PORT/tcp liberado para $r"           bash -c "grep -E '^$SSH_PORT/tcp( \(v6\))? +ALLOW IN +${r//./\\.}( |$)' <<<\"\$0\"" "$UFW_S"
done
if [[ "$(e SNMP)" == sim ]]; then
  for r in $(e SNMP_ORIGENS); do
    chk "SNMP 161/udp liberado para $r"              bash -c "grep -E '^161/udp( \(v6\))? +ALLOW IN +${r//./\\.}( |$)' <<<\"\$0\"" "$UFW_S"
  done
fi
ABERTAS=$(grep -E 'ALLOW IN +Anywhere' <<<"$UFW_S" || true)
if [[ -z "$ABERTAS" ]]; then
  echo -e "  \e[32m[OK]\e[0m    Nenhuma porta aberta para qualquer origem"; PASS=$((PASS+1))
else
  echo -e "  \e[33m[AVISO]\e[0m Portas abertas para qualquer origem (podem ser de propósito, ex.: DNS/página de bloqueio):"
  echo "$ABERTAS" | sed 's/^/            /'; AVISO=$((AVISO+1))
fi

if [[ "$(e SNMP)" == sim ]]; then
  sec "SNMPv3"
  SU=$(e SNMP_USER)
  chk "snmpd ativo e habilitado"                      bash -c "systemctl is-active --quiet snmpd && systemctl is-enabled --quiet snmpd"
  chk "snmpd escutando em $V4:161"                    bash -c "ss -ulnH | grep -q '$V4:161'"
  chk "snmpd escutando em 127.0.0.1:161"              bash -c "ss -ulnH | grep -q '127.0.0.1:161'"
  chk "rouser $SU priv"                               grep -qx "rouser $SU priv" /etc/snmp/snmpd.conf
  chk "Sem community (v1/v2c)"                        bash -c "! grep -qiE '^\s*(rocommunity|rwcommunity|com2sec)' /etc/snmp/snmpd.conf"
  chk "Usuário criado (usmUser ≥ 1, createUser = 0)"  bash -c "(( \$(grep -c '^usmUser' /var/lib/snmp/snmpd.conf) >= 1 )) && (( \$(grep -c '^createUser' /var/lib/snmp/snmpd.conf) == 0 ))"
  if [[ -t 0 ]]; then
    read -rsp "  Teste real SNMPv3? Senha de AUTENTICAÇÃO (Enter pula): " A; echo
    if [[ -n "$A" ]]; then
      read -rsp "  Senha de CRIPTOGRAFIA: " P; echo
      T=$(mktemp -d)        # senhas por arquivo 0600 temporário, nunca em argumento (apareceriam no ps)
      printf 'defVersion 3\ndefSecurityLevel authPriv\ndefSecurityName %s\ndefAuthType SHA-256\ndefAuthPassphrase %s\ndefPrivType AES\ndefPrivPassphrase %s\n' "$SU" "$A" "$P" > "$T/snmp.conf"
      chk "snmpget SNMPv3 em $V4 respondeu"           env SNMPCONFPATH="$T" snmpget "$V4" 1.3.6.1.2.1.1.3.0
      rm -rf "$T"; unset A P
    fi
  fi
fi

sec "Portas TCP em escuta (informativo)"
ss -tlnH | awk '{print "  " $4}' | sort -u

echo
echo "=============================================================="
if (( FAIL == 0 )); then
  echo -e " \e[32mRESULTADO: $PASS OK, 0 FALHA, $AVISO AVISO(S) — padrão aplicado.\e[0m"
else
  echo -e " \e[31mRESULTADO: $PASS OK, $FAIL FALHA(S), $AVISO AVISO(S) — veja as linhas [FALHA].\e[0m"
fi
echo "=============================================================="
exit $(( FAIL > 0 ))
