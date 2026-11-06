#!/usr/bin/env bash
# O volta.sh restaura SÓ o que o próprio baseline grava: 10-baseline.conf (e o arquivo da v1 que ele moveu), as regras UFW marcadas
# "baseline:" (+ políticas padrão e ativo/inativo) e o snmpd.conf se foi gerado por ele. Arquivos/regras de OUTROS produtos, mesmo
# alterados DENTRO da janela de 5 min, ficam exatamente como estavam na hora da volta.
# Sem root: ufw/systemctl/logger são simulados e os caminhos são de uma pasta temporária.
set -uo pipefail
RAIZ=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
FALHAS=0; N=0
t() { local d=$1; shift; N=$((N+1)); if "$@" >"$TMP/saida" 2>&1; then echo "    ok    $d"; else echo "    FALHA $d"; sed 's/^/          | /' "$TMP/saida"; FALHAS=$((FALHAS+1)); fi; }

ST=$TMP/stub; mkdir -p "$ST"
printf '#!/usr/bin/env bash\nexit 0\n' > "$ST/logger"
cat > "$ST/systemctl" <<'E'
#!/usr/bin/env bash
echo "systemctl $*" >> "$STUB_UFW/calls"
[[ "$*" == "is-active --quiet snmpd" ]] && exit "${STUB_SNMP_ATIVO:-0}"
exit 0
E
cat > "$ST/ufw" <<'E'
#!/usr/bin/env bash
U=$STUB_UFW
echo "ufw $*" >> "$U/calls"
[[ "$1" == --force ]] && shift
case "$1" in
  status)
    if [[ -f "$U/status_raw" ]]; then cat "$U/status_raw"
    elif [[ "${2:-}" == numbered ]]; then n=0; while IFS= read -r l; do n=$((n+1)); printf '[%2d] %s\n' "$n" "$l"; done < "$U/rules"
    else echo "Status: $(cat "$U/ativo")"; echo; cat "$U/rules"; fi;;
  delete) sed -i "${2}d" "$U/rules";;
  allow) printf '%s/%s ALLOW IN %s # %s\n' "$7" "$9" "$3" "${11}" >> "$U/rules";;
  default) echo "$2" > "$U/pol_$3";;
  reload) echo reload > "$U/ultimo";;
  disable) echo disable > "$U/ultimo"; echo inactive > "$U/ativo";;
  enable) echo enable > "$U/ultimo"; echo active > "$U/ativo";;
esac
exit 0
E
chmod +x "$ST"/*

# cenario NOME  (variáveis: ANTERIOR=1 V1=1 UFW_ANT=inactive SOCK=enabled SNMP_GER=1 SNMP_BK=0)
cenario() {
  V=$TMP/$1; SSH=$V/sshd_config.d; BK=$V/bk; U=$V/ufwstate; SNMPD=$V/snmpd.conf
  mkdir -p "$SSH" "$BK" "$U"; export STUB_UFW=$U
  printf 'ClientAliveInterval 3\n' > "$SSH/01-outro.conf"
  printf '# de outro produto\n' > "$SSH/03-vai-sumir.conf"
  printf 'PasswordAuthentication yes\n' > "$SSH/50-cloud-init.conf"
  [[ "${ANTERIOR:-0}" == 1 ]] && printf '# baseline anterior\nPort 22\n' > "$SSH/10-baseline.conf"
  [[ "${V1:-0}" == 1 ]] && printf '# arquivo da v1\n' > "$SSH/10-g2-hardening.conf"
  { [[ "${ANTERIOR:-0}" == 1 ]] && echo "44320/tcp ALLOW IN 198.51.100.7 # baseline: SSH gestao"; echo "53/udp ALLOW IN Anywhere # dns-admin"; } > "$U/rules"
  echo "${UFW_ANT:-active}" > "$U/ativo"
  printf 'DEFAULT_INPUT_POLICY="ACCEPT"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n' > "$V/default_ufw"
  [[ "${SNMP_BK:-1}" == 1 ]] && printf '# snmpd.conf original (backup)\n' > "$BK/snmpd.conf"
  cp -a "$SSH" "$BK/sshd_config.d"                                   # como o fluxo real: cópia antes de mexer
  [[ "${V1:-0}" == 1 ]] && mv "$SSH/10-g2-hardening.conf" "$BK/"     # o baseline move o arquivo da v1 para o backup
  : > "$BK/PENDENTE"
  BKX=$BK
  ( source "$RAIZ/baseline.sh"; PATH="$ST:$PATH"; TS=teste; BK=$BKX; SSHD_ARQ=$SSH/10-baseline.conf; SSHD_ANTIGO=$SSH/10-g2-hardening.conf
    SNMPD_ARQ=$SNMPD; UFW_DEFAULT_ARQ=$V/default_ufw; UFW_ANTES=${UFW_ANT:-active}; SOCKET_ANTES=${SOCK:-disabled}; gerar_volta ) > "$BK/volta.sh"
  # ---- o baseline "aplica" ----
  printf '# Gerado por baseline v2.2.1\nPort 44320\n' > "$SSH/10-baseline.conf"
  sed -i '/# baseline:/d' "$U/rules"; echo "44320/tcp ALLOW IN 203.0.113.5 # baseline: SSH gestao" >> "$U/rules"
  echo deny > "$U/pol_incoming"; echo allow > "$U/pol_outgoing"; echo active > "$U/ativo"
  if [[ "${SNMP_GER:-0}" == 1 ]]; then printf '# Gerado por baseline v2.2.1 — somente SNMPv3\nrouser x priv\n' > "$SNMPD"
  else printf '# snmpd.conf de OUTRO produto\n' > "$SNMPD"; fi
  # ---- DENTRO da janela de 5 min outros produtos mexem ----
  printf 'ClientAliveInterval 9\n# alterado dentro da janela\n' > "$SSH/01-outro.conf"
  printf '# arquivo novo de outro produto\n' > "$SSH/02-novo.conf"
  rm -f "$SSH/03-vai-sumir.conf"
  echo "8080/tcp ALLOW IN 192.0.2.99 # outro-produto" >> "$U/rules"
  : > "$U/calls"
  PATH="$ST:$PATH" bash "$BK/volta.sh" > "$V/volta.out" 2>&1
}

echo "  -- 1ª execução do baseline, UFW ativo antes, snmpd.conf de OUTRO produto"
cenario c1
t "01-outro.conf alterado dentro da janela CONTINUA como estava depois da volta" grep -qx '# alterado dentro da janela' "$SSH/01-outro.conf"
t "...com o conteúdo inteiro intacto (nada foi revertido)" bash -c '[[ "$(cat "$1")" == $'"'"'ClientAliveInterval 9\n# alterado dentro da janela'"'"' ]]' _ "$SSH/01-outro.conf"
t "arquivo criado por outro produto na janela continua"          test -f "$SSH/02-novo.conf"
t "arquivo REMOVIDO por outro produto na janela continua removido (cp -a do diretório inteiro o ressuscitaria)" test ! -e "$SSH/03-vai-sumir.conf"
t "50-cloud-init.conf intacto"                                   grep -qx 'PasswordAuthentication yes' "$SSH/50-cloud-init.conf"
t "10-baseline.conf novo removido (não havia antes)"             test ! -e "$SSH/10-baseline.conf"
t "UFW: nenhuma regra 'baseline:' sobrou (não havia antes)"      bash -c '! grep -q "# baseline:" "$1/rules"' _ "$U"
t "UFW: regra de outro produto de ANTES continua"                grep -qx '53/udp ALLOW IN Anywhere # dns-admin' "$U/rules"
t "UFW: regra de outro produto criada DENTRO da janela continua" grep -qx '8080/tcp ALLOW IN 192.0.2.99 # outro-produto' "$U/rules"
t "UFW: políticas padrão voltaram ao que eram (ACCEPT → allow)"  bash -c '[[ "$(cat "$1/pol_incoming")" == allow && "$(cat "$1/pol_outgoing")" == allow ]]' _ "$U"
t "UFW estava ativo → reload (não disable)"                      bash -c '[[ "$(cat "$1/ultimo")" == reload ]]' _ "$U"
t "snmpd.conf de OUTRO produto (sem a marca do baseline) não é tocado" grep -qx '# snmpd.conf de OUTRO produto' "$SNMPD"
t "snmpd não é reiniciado à toa"                                 bash -c '! grep -q "restart snmpd" "$1/calls"' _ "$U"
t "SSH reiniciado (ssh.service) e PENDENTE removido"             bash -c 'grep -q "systemctl restart ssh.service" "$1/calls" && [[ ! -e "$2/PENDENTE" ]]' _ "$U" "$BK"

echo "  -- execução anterior + arquivo da v1 + ssh.socket antes + UFW inativo antes + snmpd.conf gerado pelo baseline"
ANTERIOR=1 V1=1 UFW_ANT=inactive SOCK=enabled SNMP_GER=1 cenario c2
t "10-baseline.conf de ANTES é restaurado (conteúdo exato)"      bash -c '[[ "$(cat "$1")" == $'"'"'# baseline anterior\nPort 22'"'"' ]]' _ "$SSH/10-baseline.conf"
t "arquivo da v1 que o baseline moveu volta ao lugar"            grep -qx '# arquivo da v1' "$SSH/10-g2-hardening.conf"
t "01-outro.conf alterado na janela continua alterado"           grep -qx '# alterado dentro da janela' "$SSH/01-outro.conf"
t "02-novo.conf (outro produto) continua e 03 continua removido" bash -c 'test -f "$1/02-novo.conf" && test ! -e "$1/03-vai-sumir.conf"' _ "$SSH"
t "UFW: regra 'baseline:' de ANTES é recolocada"                 grep -qx '44320/tcp ALLOW IN 198.51.100.7 # baseline: SSH gestao' "$U/rules"
t "UFW: a regra 'baseline:' NOVA saiu"                           bash -c '! grep -q "203.0.113.5" "$1/rules"' _ "$U"
t "UFW: regras de outros produtos continuam (antes e na janela)" bash -c 'grep -q "dns-admin" "$1/rules" && grep -q "outro-produto" "$1/rules"' _ "$U"
t "UFW estava INATIVO → disable"                                 bash -c '[[ "$(cat "$1/ultimo")" == disable ]]' _ "$U"
t "ssh.socket reabilitado como antes"                            bash -c 'grep -q "systemctl enable ssh.socket" "$1/calls" && grep -q "systemctl restart ssh.socket" "$1/calls"' _ "$U"
t "snmpd.conf GERADO pelo baseline volta ao backup e o snmpd reinicia" bash -c 'grep -qx "# snmpd.conf original (backup)" "$1" && grep -q "restart snmpd" "$2/calls"' _ "$SNMPD" "$U"

echo "  -- snmpd.conf gerado pelo baseline mas sem backup (não existia antes)"
SNMP_BK=0 SNMP_GER=1 cenario c3
t "sem backup: o snmpd.conf não é apagado nem trocado"           grep -q '^# Gerado por baseline' "$SNMPD"

echo "  -- o script gerado"
cenario c4
t "volta.sh é bash válido"                                       bash -n "$BK/volta.sh"
t "volta.sh passa no ShellCheck (se instalado)"                  bash -c 'command -v shellcheck >/dev/null || exit 0; LC_ALL=C.UTF-8 shellcheck -S warning -e SC2050 "$1"' _ "$BK/volta.sh"
t "NÃO copia diretório inteiro de volta (sshd_config.d/. nem /etc/ufw/.)" bash -c '! grep -nE "cp -a [^ ]*/\.( |$)|/etc/ufw|sshd_config\.d/\.|cp -a .*-r|rm -rf" "$1"' _ "$BK/volta.sh"
t "o único rm -f em sshd_config.d é o do próprio 10-baseline.conf" bash -c '[[ $(grep -c "^rm -f" "$1") == 2 ]] && grep -q "^rm -f \"'"$SSH"'/10-baseline.conf\"" "$1"' _ "$BK/volta.sh"
t "sem o 01-outro.conf nem qualquer arquivo de outro produto no script" bash -c '! grep -nE "01-outro|02-novo|cloud-init|dns-admin" "$1"' _ "$BK/volta.sh"

echo "  -- ufw_estado_antes (formato real do 'ufw status')"
U2=$TMP/u2; mkdir -p "$U2"; export STUB_UFW=$U2; : > "$U2/calls"
cat > "$U2/status_raw" <<'E'
Status: active

To                         Action      From
--                         ------      ----
44320/tcp                  ALLOW       203.0.113.5                # baseline: SSH gestao
44320/tcp                  ALLOW       2001:db8::/64              # baseline: SSH gestao
44320/tcp (v6)             ALLOW       2001:db8::/64              # baseline: SSH gestao
161/udp                    ALLOW       192.0.2.51                 # baseline: SNMP
53/udp                     ALLOW       Anywhere                   # dns-admin
22/tcp                     ALLOW       10.0.0.1                   # baseline: x'; touch /tmp/pwn-volta
80/tcp                     ALLOW       10.0.0.2                   # baseline: ok $(id)
E
printf 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n' > "$TMP/default_u2"
( source "$RAIZ/baseline.sh"; PATH="$ST:$PATH"; UFW_DEFAULT_ARQ=$TMP/default_u2; ufw_estado_antes ) > "$TMP/estado.out"
t "reconhece só as regras do baseline, sem duplicar a (v6)"       bash -c '[[ $(grep -c "^ufw allow" "$1") == 3 ]]' _ "$TMP/estado.out"
t "comandos gerados exatos"                                       bash -c '
  grep -qx "ufw allow from '"'"'203.0.113.5'"'"' to any port 44320 proto tcp comment '"'"'baseline: SSH gestao'"'"' >/dev/null" "$1" &&
  grep -qx "ufw allow from '"'"'2001:db8::/64'"'"' to any port 44320 proto tcp comment '"'"'baseline: SSH gestao'"'"' >/dev/null" "$1" &&
  grep -qx "ufw allow from '"'"'192.0.2.51'"'"' to any port 161 proto udp comment '"'"'baseline: SNMP'"'"' >/dev/null" "$1"' _ "$TMP/estado.out"
t "comentário com aspas/\$() é recusado (nada de injeção no volta.sh)" bash -c '! grep -qE "pwn-volta|\$\(id\)|10\.0\.0\.[12]" "$1"' _ "$TMP/estado.out"
t "regra de outro produto (Anywhere, dns-admin) não é recolocada" bash -c '! grep -q "dns-admin\|53" "$1"' _ "$TMP/estado.out"
t "políticas padrão (DROP → deny, ACCEPT → allow)"                bash -c 'grep -qx "ufw default deny incoming >/dev/null" "$1" && grep -qx "ufw default allow outgoing >/dev/null" "$1"' _ "$TMP/estado.out"
t "nada foi escrito: só leitura (ufw status)"                      bash -c '! grep -vE "^ufw status" "$1"' _ "$U2/calls"

echo
(( FALHAS )) && { echo "    volta.sh: $FALHAS de $N falharam"; exit 1; }
echo "    volta.sh: $N verificações passaram"
