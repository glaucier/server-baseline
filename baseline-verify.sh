#!/usr/bin/env bash
# =============================================================================
# baseline-verify.sh — confere o padrão aplicado pelo baseline.sh
# Uso: sudo baseline-verify        (ou sudo bash baseline-verify.sh)
# SÓ LEITURA: não altera nada. Saída 0 = tudo OK; 1 = alguma FALHA.
# Lê /root/baseline.env (respostas da última execução, sem senha) — sem executá-lo.
# =============================================================================
set -uo pipefail
PASS=0; FAIL=0; AVISO=0

ENV_FILE=/root/baseline.env
declare -A E=()
e() { echo "${E[$1]:-}"; }

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
sim_yn() { [[ "$1" == sim ]] && echo yes || echo no; }

# SSH efetivo (saída do `sshd -T -C user=…`, que respeita Match) contra o que o baseline registrou.
# Chaves ausentes (env da v2.0.0) viram AVISO, não FALHA. AllowUsers: conjunto EXATO (a diretiva acumula entre arquivos).
confere_ssh_efetivo() { # $1 = saída do sshd -T
  local T=$1 k v par esp efet
  for par in "SSH_TCP_FWD allowtcpforwarding" "SSH_AGENT_FWD allowagentforwarding"; do
    k=${par% *}; v=${par#* }
    if [[ -z "$(e "$k")" ]]; then avs "sshd efetivo: $v (não registrado: baseline anterior à v2.1.0 — rode o baseline de novo)" false; continue; fi
    chk "sshd efetivo: $v $(sim_yn "$(e "$k")")" grep -qx "$v $(sim_yn "$(e "$k")")" <<<"$T"
  done
  for par in "SSH_GRACE logingracetime" "SSH_ALIVE_INT clientaliveinterval" "SSH_ALIVE_MAX clientalivecountmax"; do
    k=${par% *}; v=${par#* }
    if [[ -z "$(e "$k")" ]]; then avs "sshd efetivo: $v (não registrado: baseline anterior à v2.1.0 — rode o baseline de novo)" false; continue; fi
    chk "sshd efetivo: $v $(e "$k")" grep -qx "$v $(e "$k")" <<<"$T"
  done
  if [[ -z "$(e SSH_USUARIOS)" ]]; then
    avs "sshd efetivo: allowusers (não registrado: baseline anterior à v2.1.0 — rode o baseline de novo)" false
  else
    esp=$(tr ' ' '\n' <<<"$(e SSH_USUARIOS)" | sort | tr '\n' ' ')
    efet=$(awk '$1=="allowusers"{print $2}' <<<"$T" | sort | tr '\n' ' ')
    chk "sshd efetivo: allowusers = $(e SSH_USUARIOS) (sem usuário a mais nem a menos; efetivo: ${efet:-nenhum})" igual "$efet" "$esp"
  fi
}

# Permissão: dono root e nenhum bit de grupo/outros. $1 = arquivo ou pasta
so_root() { local m o; m=$(stat -c '%a' "$1" 2>/dev/null) || return 1; o=$(stat -c '%U' "$1"); [[ "$o" == root ]] && (( (8#$m & 8#077) == 0 )); }

# Guard: `source baseline-verify.sh` nos testes (tests/run.sh) só traz as funções
[[ "${BASH_SOURCE[0]}" != "$0" ]] && return 0

[[ $EUID -eq 0 ]] || { echo "Rode como root: sudo baseline-verify"; exit 1; }
[[ -r "$ENV_FILE" ]] || { echo "Não achei $ENV_FILE — rode o baseline antes."; exit 1; }
while IFS= read -r linha || [[ -n "$linha" ]]; do
  [[ -z "$linha" || "$linha" == \#* || "$linha" != *=* ]] && continue
  k="${linha%%=*}"; v="${linha#*=}"
  [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
  [[ "$v" == \"*\" && ${#v} -ge 2 ]] && v="${v:1:${#v}-2}"
  E[$k]="$v"
done < "$ENV_FILE"

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

sec "Confirmação do baseline"
PEND=$(compgen -G '/root/baseline-backup-*/PENDENTE' || true)
if [[ -z "$PEND" ]]; then
  echo -e "  \e[32m[OK]\e[0m    Nenhuma execução do baseline pendente de confirmação"; PASS=$((PASS+1))
else
  echo -e "  \e[33m[AVISO]\e[0m Baseline NUNCA confirmado (sem o OK): pode ter havido reboot antes do OK, que desarma a volta automática."
  while read -r f; do echo "            $f — para desfazer: sudo bash $(dirname "$f")/volta.sh"; done <<<"$PEND"
  echo "            Se o acesso novo funciona, rode o baseline de novo e confirme com OK (isso limpa o aviso)."; AVISO=$((AVISO+1))
fi

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
# Efetivo COM os blocos Match, para o administrador, vindo de um IP de gestão (ou do loopback)
ADDR_GESTAO=$(awk '{print $1}' <<<"$(e GESTAO_SSH)"); ADDR_GESTAO=${ADDR_GESTAO%%/*}
SSHD_T=$(sshd -T -C "user=$ADMIN_USER,host=localhost,addr=${ADDR_GESTAO:-127.0.0.1}" 2>/dev/null)
for par in "port $SSH_PORT" "permitrootlogin no" "passwordauthentication no" "kbdinteractiveauthentication no" "pubkeyauthentication yes"; do
  chk "sshd efetivo: $par"                            grep -qx "$par" <<<"$SSHD_T"
done
confere_ssh_efetivo "$SSHD_T"
HOME_ADM=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
AK_FPS=$(ssh-keygen -lf "$HOME_ADM/.ssh/authorized_keys" 2>/dev/null)
for fp in $(e PUBKEY_FPS); do
  chk "Chave $fp autorizada para $ADMIN_USER"        grep -qF "$fp" <<<"$AK_FPS"
done
chk "Sem chave de autoteste esquecida no authorized_keys"  bash -c "! grep -qF 'baseline-selftest-' '$HOME_ADM/.ssh/authorized_keys'"
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

sec "Arquivos sensíveis (só o root)"
chk "$ENV_FILE só do root (sem acesso a grupo/outros)"   so_root "$ENV_FILE"
for f in /root/baseline-*.log; do
  [[ -e "$f" ]] || continue
  chk "$f só do root (600)"                                so_root "$f"
done
for f in /root/baseline-backup-*/; do
  [[ -d "$f" ]] || continue
  chk "$f só do root (700)"                                so_root "$f"
done

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
