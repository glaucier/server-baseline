#!/usr/bin/env bash
# =============================================================================
# baseline.sh — padrão inicial para servidores Ubuntu 24.04 LTS
#
#   1. Sistema: fuso horário, nome do servidor, atualização e atualização automática
#   2. IPv6 estático derivado do IPv4 (opcional)
#   3. SSH: porta própria, só chave, sem root + firewall UFW (com VOLTA AUTOMÁTICA)
#   4. SNMPv3 somente leitura, authPriv (SHA-256/AES), sem community (opcional)
#
# Uso (no servidor, como root):
#   sudo bash baseline.sh                      # pergunta tudo, com exemplo e padrão
#   sudo bash baseline.sh --respostas ARQ      # usa as respostas do arquivo (o que faltar, pergunta)
#   sudo bash baseline.sh --ajuda
# Depois: reboot  →  sudo baseline-verify
#
# Nada aqui é fixo de uma empresa: redes, chave, portas e SNMP são perguntados. As respostas
# (SEM senha) ficam em /root/baseline.env e viram o padrão da próxima execução.
# Senhas nunca vão para log, arquivo de respostas nem argumento de comando.
# =============================================================================
set -uo pipefail

VERSAO="2.0.0"
ENV_FILE=/root/baseline.env
ENV_ANTIGO=/root/g2-baseline.env          # v1 (g2-baseline): lido como padrão, nunca alterado
TS=$(date +%Y%m%d-%H%M%S)
LOG=/root/baseline-$TS.log
BK=/root/baseline-backup-$TS
SSHD_ARQ=/etc/ssh/sshd_config.d/10-baseline.conf
SSHD_ANTIGO=/etc/ssh/sshd_config.d/10-g2-hardening.conf
VOLTA_MIN=5

# ---- Saída -------------------------------------------------------------------------------------
info() { echo -e "\n\e[1;36m==> $*\e[0m"; }
ok()   { echo -e "  \e[32m[OK]\e[0m $*"; }
aviso(){ echo -e "  \e[33m[AVISO]\e[0m $*"; }
pare() { echo -e "  \e[31m[ERRO]\e[0m $*"; echo "Abortado. Log: $LOG"; exit 1; }

ajuda() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Arquivo de respostas: o mesmo formato de /root/baseline.env (CHAVE="valor", uma por linha).
O /root/baseline.env de um servidor serve de modelo para o próximo (troque HOSTNAME_ e V6).
Chaves: TZ_ HOSTNAME_ ATUALIZAR_AGORA HORA ATUALIZA_SEGURAR V6_ATIVAR V6_PREFIXO V6 V6_GW
        ADMIN_USER PUBKEY SSH_PORT GESTAO_SSH SNMP SNMP_ORIGENS SNMP_USER SNMP_LOCATION SNMP_CONTACT
EOF
}

# ---- Leitura de CHAVE=valor sem executar o arquivo (nunca `source`) ----------------------------
declare -A PADRAO=() RESP=()
ler_kv() { # $1 = arquivo, $2 = nome do array associativo
  local -n _alvo=$2
  local linha k v
  [[ -r "$1" ]] || return 0
  while IFS= read -r linha || [[ -n "$linha" ]]; do
    linha="${linha#"${linha%%[![:space:]]*}"}"
    [[ -z "$linha" || "$linha" == \#* || "$linha" != *=* ]] && continue
    k="${linha%%=*}"; v="${linha#*=}"
    k="${k#export }"
    [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
    v="${v%"${v##*[![:space:]]}"}"
    [[ "$v" == \"*\" && ${#v} -ge 2 ]] && v="${v:1:${#v}-2}"
    _alvo[$k]="$v"
  done < "$1"
}

# ---- Validação (Python ipaddress; o valor vai por argumento, nunca dentro do código) -----------
VALOR=""
py_rede() { python3 -I - "$@" <<'PY'
import ipaddress, sys
tipo, v = sys.argv[1], sys.argv[2].strip()
try:
    if tipo == "ipv4":
        print(ipaddress.IPv4Address(v))
    elif tipo == "ipv6":
        a = ipaddress.IPv6Address(v)
        if a.is_link_local or a.is_loopback or a.is_multicast or a.is_unspecified: sys.exit(1)
        print(a.compressed)
    elif tipo == "rede":                         # IP ou rede (v4/v6) para o UFW
        n = ipaddress.ip_network(v, strict=False)
        if n.prefixlen == 0: sys.exit(1)         # 0.0.0.0/0 não é "rede de gestão"
        print(n.network_address.compressed if n.num_addresses == 1 else n.with_prefixlen)
    elif tipo == "prefixo64":                    # aceita 2001:db8:100:1 ou 2001:db8:100:1::/64
        t = v if "/" in v else v.rstrip(":") + "::/64"
        n = ipaddress.IPv6Network(t, strict=False)
        if n.prefixlen != 64: sys.exit(1)
        print(n.with_prefixlen)
    elif tipo == "deriva":                       # prefixo/64 + texto (ex. "12") lido como hexadecimal
        n = ipaddress.IPv6Network(v); suf = int(sys.argv[3], 16)
        print(ipaddress.IPv6Address(int(n.network_address) + suf).compressed)
    elif tipo == "prefixo_de":                   # IPv6 → seu /64
        print(ipaddress.IPv6Network(v + "/64", strict=False).with_prefixlen)
    elif tipo == "contem":                       # IP $2 está em alguma rede de $3..?
        ip = ipaddress.ip_address(v)
        sys.exit(0 if any(ip in ipaddress.ip_network(r, strict=False) for r in sys.argv[3:]) else 1)
    else:
        sys.exit(2)
except (ValueError, IndexError):
    sys.exit(1)
PY
}

val_ipv6()     { VALOR=$(py_rede ipv6 "$1"); }
val_prefixo()  { VALOR=$(py_rede prefixo64 "$1"); }
val_hora()     { [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] && VALOR="$1"; }
val_porta()    { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )) && VALOR=$((10#$1)); }
val_tz()       { timedatectl list-timezones 2>/dev/null | grep -qxF -- "$1" && VALOR="$1"; }
val_hostname() { [[ "${1,,}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] && VALOR="${1,,}"; }
val_usuario()  { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && id "$1" >/dev/null 2>&1 && VALOR="$1"; }
val_simnao()   { case "${1,,}" in s|sim|y|yes) VALOR=sim;; n|nao|não|no) VALOR=nao;; *) return 1;; esac; }
val_texto()    { [[ -n "$1" && ${#1} -le 64 && "$1" != *[\"\\\$\`]* ]] && VALOR="$1"; }
val_pacotes()  { # vazio = nenhum
  local p r=""
  for p in ${1//,/ }; do [[ "$p" =~ ^[a-z0-9][a-z0-9+.-]+$ ]] || return 1; r+="${r:+ }$p"; done
  VALOR="$r"; return 0; }
val_redes()    { # lista de IPs/redes separados por espaço ou vírgula
  local r n saida=""
  for r in ${1//,/ }; do n=$(py_rede rede "$r") || { echo "    \"$r\" não é IP nem rede válida"; return 1; }; saida+="${saida:+ }$n"; done
  [[ -n "$saida" ]] && VALOR="$saida"; }

# ---- Pergunta com explicação, exemplo e padrão --------------------------------------------------
# pergunta VAR "Título" "Explicação" "Exemplo" "padrão" validador [aceita_vazio]
pergunta() {
  local var=$1 titulo=$2 expl=$3 exemplo=$4 padrao=$5 validador=$6 vazio=${7:-nao} r
  if [[ -n "${RESP[$var]+x}" ]]; then
    r=${RESP[$var]}
    if [[ -z "$r" && "$vazio" == sim ]] || { [[ -n "$r" ]] && $validador "$r"; }; then
      [[ -z "$r" ]] && VALOR=""
      printf -v "$var" '%s' "$VALOR"; echo "  $titulo: ${VALOR:-(vazio)}   (arquivo de respostas)"; return 0
    fi
    pare "$var=\"$r\" do arquivo de respostas é inválido — $titulo"
  fi
  echo
  echo -e "\e[1m$titulo\e[0m"
  [[ -n "$expl" ]] && echo "$expl" | sed 's/^/  /'
  [[ -n "$exemplo" ]] && echo "  Exemplo: $exemplo"
  while :; do
    read -rp "  > [${padrao:-vazio}]: " r </dev/tty
    r=${r:-$padrao}
    if [[ -z "$r" ]]; then
      [[ "$vazio" == sim ]] && { printf -v "$var" '%s' ""; return 0; }
      echo "    Resposta obrigatória."; continue
    fi
    if $validador "$r"; then printf -v "$var" '%s' "$VALOR"; return 0; fi
    echo "    Valor inválido, tente de novo."
  done
}

ler_senha() { # $1 = rótulo ; resultado em SENHA (só interativo)
  local s1 s2
  while :; do
    read -rsp "  $1 (8+ caracteres, sem espaço, aspas, \\, \$ ou \`): " s1 </dev/tty; echo
    read -rsp "  Repita: " s2 </dev/tty; echo
    [[ "$s1" == "$s2" ]] || { echo "    Senhas diferentes."; continue; }
    (( ${#s1} >= 8 )) || { echo "    Muito curta."; continue; }
    [[ "$s1" == *[[:space:]\"\'\\\$\`]* ]] && { echo "    Caractere não permitido."; continue; }
    SENHA=$s1; break
  done
}

# ---- Argumentos ---------------------------------------------------------------------------------
ARQ_RESP=""
while (( $# )); do
  case "$1" in
    --respostas) [[ -n "${2:-}" ]] || { echo "--respostas exige um arquivo"; exit 1; }; ARQ_RESP=$2; shift 2;;
    --ajuda|-h|--help) ajuda; exit 0;;
    *) echo "Opção desconhecida: $1 (use --ajuda)"; exit 1;;
  esac
done

# ---- Pré-requisitos -----------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || { echo "Rode como root: sudo bash $0"; exit 1; }
if [[ -n "$ARQ_RESP" ]]; then
  [[ -r "$ARQ_RESP" ]] || { echo "Não consigo ler $ARQ_RESP"; exit 1; }
  ler_kv "$ARQ_RESP" RESP
fi
umask 077
exec > >(tee -a "$LOG") 2>&1

# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || pare "Feito para Ubuntu 24.04 LTS (encontrado: ${PRETTY_NAME:-?})"
command -v python3 >/dev/null || pare "python3 ausente (vem no Ubuntu Server; instale com: apt install python3)"

# Padrões: execução anterior (v2) > v1 (g2-baseline.env) > padrão do script
if [[ -r "$ENV_FILE" ]]; then
  ler_kv "$ENV_FILE" PADRAO; ORIGEM_PADRAO="$ENV_FILE"
elif [[ -r "$ENV_ANTIGO" ]]; then
  ler_kv "$ENV_ANTIGO" PADRAO; ORIGEM_PADRAO="$ENV_ANTIGO (v1)"
  [[ -n "${PADRAO[PRTG_IP]:-}" ]] && { PADRAO[SNMP]=sim; PADRAO[SNMP_ORIGENS]=${PADRAO[PRTG_IP]}; }
  [[ -n "${PADRAO[PUBKEY_FP]:-}" ]] && PADRAO[PUBKEY_FPS]=${PADRAO[PUBKEY_FP]}
else
  ORIGEM_PADRAO="(primeira execução)"
fi
p() { echo "${PADRAO[$1]:-${2:-}}"; }

# Detecção: interface e gateway da ROTA PADRÃO (não "a primeira interface")
IF=$(ip -4 route show default 2>/dev/null | awk '/default/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
V4_GW=$(ip -4 route show default 2>/dev/null | awk '/default/{print $3; exit}')
[[ -n "$IF" && -n "$V4_GW" ]] || pare "Sem rota padrão IPv4. Configure o IPv4 (endereço, gateway, DNS) na instalação do Ubuntu e rode de novo."
V4_CIDR=$(ip -4 -o addr show dev "$IF" scope global 2>/dev/null | awk '{print $4; exit}')
V4=${V4_CIDR%/*}
[[ -n "$V4" ]] || pare "Interface $IF sem IPv4 global."
OCT=${V4##*.}
CLIENTE_SSH=${SSH_CLIENT:-}; CLIENTE_SSH=${CLIENTE_SSH%% *}
# sudo apaga SSH_CLIENT: o "who -m" diz de onde veio esta sessão
[[ -z "$CLIENTE_SSH" ]] && CLIENTE_SSH=$(who -m 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p')
[[ -n "$CLIENTE_SSH" ]] && { CLIENTE_SSH=$(py_rede ipv4 "$CLIENTE_SSH" || py_rede ipv6 "$CLIENTE_SSH") || CLIENTE_SSH=""; }

echo "=============================================================="
echo " baseline v$VERSAO — $(hostname) — $(date '+%F %T')"
echo " Interface: $IF   IPv4: $V4_CIDR   gateway: $V4_GW"
echo " Padrões de: $ORIGEM_PADRAO"
[[ -n "$CLIENTE_SSH" ]] && echo " Você está conectado por SSH a partir de: $CLIENTE_SSH"
echo " Enter aceita o valor entre [colchetes]. Nada é alterado antes do resumo final."
echo "=============================================================="

# =================================================================================================
# PERGUNTAS
# =================================================================================================
info "Sistema"
pergunta TZ_ "Fuso horário" "Usado nos logs e nos horários de atualização." "America/Sao_Paulo" "$(p TZ_ America/Sao_Paulo)" val_tz
pergunta HOSTNAME_ "Nome do servidor (hostname)" "Curto, sem domínio: letras, números e hífen." "dns1, web01" "$(p HOSTNAME_ "$(hostname -s)")" val_hostname
pergunta ATUALIZAR_AGORA "Atualizar o sistema agora (apt full-upgrade)?" \
"Em VM nova: s. Em servidor já em produção: n — a atualização pode reiniciar serviços.
Responda s ou n." "s" "$( [[ "$ORIGEM_PADRAO" == "(primeira execução)" ]] && echo sim || echo nao )" val_simnao
pergunta HORA "Horário da atualização automática diária (HH:MM)" \
"Só atualizações de segurança. Servidores redundantes (ex.: dois DNS) devem ter horários DIFERENTES." \
"06:00 no primeiro, 07:00 no segundo" "$(p HORA 07:00)" val_hora
pergunta ATUALIZA_SEGURAR "Pacotes que a atualização automática NÃO deve tocar" \
"Separe por espaço. Em servidor DNS use: unbound (reiniciar o unbound zera o cache; atualize-o pelo painel).
Enter vazio = nenhum." "unbound" "$(p ATUALIZA_SEGURAR)" val_pacotes sim

info "IPv6"
V6_ATUAL=$(ip -6 -o addr show dev "$IF" scope global 2>/dev/null | awk '$0 !~ /temporary|dynamic/ {print $4; exit}')
if [[ -n "$V6_ATUAL" ]]; then echo "  IPv6 global já presente em $IF: $V6_ATUAL"; fi
pergunta V6_ATIVAR "Configurar IPv6 estático nesta interface?" \
"O endereço é derivado do IPv4 (último octeto). Responda n se não houver IPv6 nesta rede." "s" "$(p V6_ATIVAR "$( [[ -n "$(p V6)" ]] && echo sim || echo nao )")" val_simnao
if [[ "$V6_ATIVAR" == sim ]]; then
  PREF_PADRAO=$(p V6_PREFIXO); [[ -z "$PREF_PADRAO" && -n "$(p V6)" ]] && PREF_PADRAO=$(py_rede prefixo_de "$(p V6)")
  pergunta V6_PREFIXO "Prefixo IPv6 /64 da rede dos servidores" "O mesmo /64 em que está o gateway IPv6." "2001:db8:100:1::/64" "$PREF_PADRAO" val_prefixo
  V6_SUG=$(py_rede deriva "$V6_PREFIXO" "$OCT") || V6_SUG=""
  [[ -n "$(p V6)" && "$(py_rede prefixo_de "$(p V6)")" == "$V6_PREFIXO" && "$(p HOSTNAME_)" == "$HOSTNAME_" ]] && V6_SUG=$(p V6)
  pergunta V6 "IPv6 deste servidor" "Sugestão: prefixo + o último octeto do IPv4 ($OCT) escrito igual." "${V6_PREFIXO%%::*}::$OCT" "$V6_SUG" val_ipv6
  [[ "$(py_rede prefixo_de "$V6")" == "$V6_PREFIXO" ]] || pare "O IPv6 $V6 não está no prefixo $V6_PREFIXO"
  GW_SUG=$(p V6_GW); [[ -z "$GW_SUG" || "$(py_rede prefixo_de "$GW_SUG" 2>/dev/null)" != "$V6_PREFIXO" ]] && GW_SUG=$(py_rede deriva "$V6_PREFIXO" 1)
  pergunta V6_GW "Gateway IPv6" "Normalmente o ::1 do prefixo." "${V6_PREFIXO%%::*}::1" "$GW_SUG" val_ipv6
else
  V6=""; V6_GW=""; V6_PREFIXO=""
fi

info "Acesso SSH"
pergunta ADMIN_USER "Usuário administrador (precisa existir e ter sudo)" "O usuário criado na instalação do Ubuntu." "admin" "$(p ADMIN_USER "${SUDO_USER:-}")" val_usuario
id -nG "$ADMIN_USER" | grep -qw sudo || aviso "$ADMIN_USER não está no grupo sudo — sem ele, depois do baseline você não terá root (sem login de root por SSH)."
H=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
AK="$H/.ssh/authorized_keys"
FPS_ATUAIS=$(ssh-keygen -lf "$AK" 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
PUBKEY=""
if [[ -n "${RESP[PUBKEY]+x}" ]]; then
  PUBKEY=${RESP[PUBKEY]}
elif [[ -n "$FPS_ATUAIS" ]]; then
  echo; echo "  Chaves já autorizadas para $ADMIN_USER:"; ssh-keygen -lf "$AK" 2>/dev/null | sed 's/^/    /'
  read -rp "  Adicionar outra chave pública? (s/N): " r </dev/tty
  [[ "${r,,}" =~ ^s ]] && read -rp "  Cole a chave pública (uma linha, ssh-ed25519 …): " PUBKEY </dev/tty
else
  echo; echo -e "\e[1mChave pública SSH do administrador\e[0m"
  echo "  O login por senha será DESLIGADO: sem esta chave você só entra pelo console da VM."
  echo "  No Termius: Keychain → a chave → Export/Copy public key. No Linux/Mac: cat ~/.ssh/id_ed25519.pub"
  echo "  Exemplo: ssh-ed25519 AAAAC3Nza…resto… usuario@notebook"
  read -rp "  Cole a chave pública: " PUBKEY </dev/tty
fi
NOVO_FP=""
if [[ -n "$PUBKEY" ]]; then
  TMPK=$(mktemp); printf '%s\n' "$PUBKEY" > "$TMPK"
  NOVO_FP=$(ssh-keygen -lf "$TMPK" 2>/dev/null | awk '{print $2}'); rm -f "$TMPK"
  [[ -n "$NOVO_FP" && "$PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))\  ]] || pare "Isso não é uma chave pública SSH válida (deve começar com ssh-ed25519, ssh-rsa ou ecdsa-…)"
  echo "  Impressão digital da chave colada: $NOVO_FP"
  echo "  Confira se é a MESMA mostrada no seu cliente SSH (Termius: detalhes da chave)."
  if [[ -z "${RESP[PUBKEY]+x}" ]]; then read -rp "  Confere? (s/N): " r </dev/tty; [[ "${r,,}" =~ ^s ]] || pare "Chave não confirmada (nada foi alterado)"; fi
fi
[[ -n "$FPS_ATUAIS$NOVO_FP" ]] || pare "Nenhuma chave SSH para $ADMIN_USER — sem chave, desligar a senha trancaria você fora."

pergunta SSH_PORT "Porta do SSH" "Evite a 22 (alvo de varredura automática)." "44320" "$(p SSH_PORT 44320)" val_porta
pergunta GESTAO_SSH "IPs/redes que podem acessar o SSH (gestão)" \
"Só estes passam no firewall para o SSH. Separe por espaço. Aceita IPv4, IPv6 e redes com /máscara." \
"192.0.2.10 198.51.100.0/24 2001:db8::/48" "$(p GESTAO_SSH "$CLIENTE_SSH")" val_redes
if [[ -n "$CLIENTE_SSH" ]] && ! py_rede contem "$CLIENTE_SSH" $GESTAO_SSH; then
  aviso "Você está conectado de $CLIENTE_SSH, que NÃO está na lista de gestão."
  read -rp "  Incluir $CLIENTE_SSH na gestão? (S/n): " r </dev/tty
  [[ "${r,,}" =~ ^n ]] || GESTAO_SSH+=" $(py_rede rede "$CLIENTE_SSH")"
fi

info "SNMP"
pergunta SNMP "Configurar SNMPv3 (monitoramento, ex.: PRTG, Zabbix, LibreNMS)?" "Somente leitura, com usuário e duas senhas; sem community v1/v2c." "s" "$(p SNMP sim)" val_simnao
AUTH=""; PRIV=""; SNMP_TROCA_SENHA=nao
if [[ "$SNMP" == sim ]]; then
  pergunta SNMP_ORIGENS "IPs/redes do servidor de monitoramento" "Só estes consultam a porta 161/udp." "192.0.2.51" "$(p SNMP_ORIGENS)" val_redes
  pergunta SNMP_USER "Usuário SNMPv3" "O mesmo cadastrado no sensor do monitoramento." "monitorv3" "$(p SNMP_USER)" val_texto
  pergunta SNMP_LOCATION "Localização (sysLocation)" "Onde o servidor está; aparece no monitoramento." "Datacenter_Central" "$(p SNMP_LOCATION)" val_texto
  pergunta SNMP_CONTACT "Contato (sysContact)" "E-mail do responsável." "suporte@exemplo.com.br" "$(p SNMP_CONTACT)" val_texto
  TEM_USM=$(grep -c '^usmUser' /var/lib/snmp/snmpd.conf 2>/dev/null); TEM_USM=${TEM_USM:-0}
  if (( TEM_USM > 0 )) && [[ "$(p SNMP_USER)" == "$SNMP_USER" ]]; then
    read -rp "  O usuário $SNMP_USER já existe. Trocar as senhas? (s/N): " r </dev/tty
    [[ "${r,,}" =~ ^s ]] && SNMP_TROCA_SENHA=sim
  else
    SNMP_TROCA_SENHA=sim
  fi
  if [[ "$SNMP_TROCA_SENHA" == sim ]]; then
    echo "  As senhas são as que você vai cadastrar no monitoramento (SHA-256 / AES). Não ficam gravadas em lugar nenhum."
    ler_senha "Senha de AUTENTICAÇÃO"; AUTH=$SENHA
    ler_senha "Senha de CRIPTOGRAFIA "; PRIV=$SENHA
    unset SENHA
    [[ "$AUTH" == "$PRIV" ]] && aviso "Senhas de autenticação e criptografia iguais — funciona, mas o recomendado é diferentes."
  fi
else
  SNMP_ORIGENS=""; SNMP_USER=""; SNMP_LOCATION=""; SNMP_CONTACT=""
fi

# =================================================================================================
# RESUMO
# =================================================================================================
SOCKET_ANTES=$(systemctl is-enabled ssh.socket 2>/dev/null || true)
UFW_ANTES=$(ufw status 2>/dev/null | awk '/^Status:/{print $2}')
echo
echo "=============================================================="
echo " RESUMO — nada foi alterado ainda"
echo "=============================================================="
echo "  Fuso / nome ........: $TZ_ / $HOSTNAME_"
echo "  Atualizar agora ....: $ATUALIZAR_AGORA"
echo "  Atualização auto ...: todo dia às $HORA (só segurança, sem reboot automático)"
echo "  Fora da auto .......: ${ATUALIZA_SEGURAR:-(nenhum)}"
if [[ -n "$V6" ]]; then echo "  IPv6 ...............: $V6/64  gateway $V6_GW  ($IF)"; else echo "  IPv6 ...............: não configurar"; fi
echo "  SSH ................: porta $SSH_PORT, só chave, sem root, usuário $ADMIN_USER"
[[ -n "$NOVO_FP" ]] && echo "  Chave nova .........: $NOVO_FP"
echo "  UFW (entrada) ......: negar tudo, exceto:"
echo "      SSH $SSH_PORT/tcp de: $GESTAO_SSH"
[[ "$SNMP" == sim ]] && echo "      SNMP 161/udp de: $SNMP_ORIGENS"
echo "      (estado atual do UFW: ${UFW_ANTES:-desconhecido}; regras de outros programas são mantidas)"
if [[ "$SNMP" == sim ]]; then
  echo "  SNMPv3 .............: usuário $SNMP_USER (authPriv SHA-256/AES), escuta $V4 e 127.0.0.1"
  echo "                        senhas: $([[ $SNMP_TROCA_SENHA == sim ]] && echo 'novas' || echo 'mantidas')"
fi
echo "  Proteção ...........: se o novo acesso SSH não for confirmado em $VOLTA_MIN min, SSH e UFW voltam sozinhos"
echo "  Cópias .............: $BK"
read -rp "Aplicar? (s/N): " C </dev/tty
[[ "${C,,}" =~ ^s ]] || pare "Cancelado (nada foi alterado)"

mkdir -p "$BK"
cp -a /etc/ssh/sshd_config.d "$BK/sshd_config.d" 2>/dev/null
cp -a /etc/netplan "$BK/netplan" 2>/dev/null
cp -a /etc/ufw "$BK/ufw" 2>/dev/null
cp -a /etc/snmp/snmpd.conf "$BK/" 2>/dev/null
cp -a /etc/hosts /etc/hostname "$BK/" 2>/dev/null

# =================================================================================================
# 1. SISTEMA
# =================================================================================================
info "1/4 Sistema"
timedatectl set-timezone "$TZ_" && ok "Fuso $TZ_"
if [[ "$(hostname)" != "$HOSTNAME_" ]]; then
  hostnamectl set-hostname "$HOSTNAME_" || pare "hostnamectl falhou"
  if grep -q '^127\.0\.1\.1[[:space:]]' /etc/hosts; then sed -i "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1 $HOSTNAME_/" /etc/hosts
  else echo "127.0.1.1 $HOSTNAME_" >> /etc/hosts; fi
  if [[ -d /etc/cloud/cloud.cfg.d ]] && [[ ! -f /etc/cloud/cloud-init.disabled ]]; then   # cloud-init ativo trocaria o nome no boot
    printf '# baseline: manter o hostname definido pelo administrador\npreserve_hostname: true\n' > /etc/cloud/cloud.cfg.d/99-baseline-hostname.cfg
  fi
  ok "Nome do servidor: $HOSTNAME_"
fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
apt-get update -q >/dev/null || pare "apt-get update falhou (internet/DNS do servidor?)"
if [[ "$ATUALIZAR_AGORA" == sim ]]; then
  apt-get "${APT_OPTS[@]}" full-upgrade >/dev/null || pare "full-upgrade falhou"; ok "Sistema atualizado"
fi
PKGS=(unattended-upgrades ufw)
[[ "$SNMP" == sim ]] && PKGS+=(snmpd snmp)
apt-get "${APT_OPTS[@]}" install "${PKGS[@]}" >/dev/null || pare "Instalação de pacotes falhou"
ok "Pacotes: ${PKGS[*]}"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
{
  echo "// Gerado por baseline v$VERSAO em $(date '+%F %T') — não edite à mão; rode o baseline de novo"
  echo 'Unattended-Upgrade::Automatic-Reboot "false";'
  if [[ -n "$ATUALIZA_SEGURAR" ]]; then
    printf 'Unattended-Upgrade::Package-Blacklist {'; for x in $ATUALIZA_SEGURAR; do printf ' "%s";' "$x"; done; echo ' };'
  fi
} > /etc/apt/apt.conf.d/52baseline
chmod 644 /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/52baseline
mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d
printf '[Timer]\nOnCalendar=\nOnCalendar=*-*-* %s\nRandomizedDelaySec=0\n' "$HORA" > /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf
chmod 644 /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf
systemctl daemon-reload && systemctl enable apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 \
  && systemctl restart apt-daily.timer apt-daily-upgrade.timer && ok "Atualização automática às $HORA${ATUALIZA_SEGURAR:+ (fora: $ATUALIZA_SEGURAR)}"

# =================================================================================================
# 2. IPv6
# =================================================================================================
info "2/4 IPv6"
if [[ -n "$V6" ]]; then
  # Duplicidade: o kernel testa o endereço (DAD) antes de usá-lo. Se outro host já o usa → "dadfailed".
  if ! ip -6 addr show dev "$IF" | grep -qi " $V6/64"; then
    ip -6 addr add "$V6/64" dev "$IF" 2>/dev/null && sleep 3
    if ip -6 addr show dev "$IF" | grep -i " $V6/64" | grep -q dadfailed; then
      ip -6 addr del "$V6/64" dev "$IF" 2>/dev/null
      pare "O IPv6 $V6 JÁ ESTÁ EM USO por outro equipamento nesta rede (DAD). Escolha outro e rode de novo."
    fi
    ok "IPv6 $V6 livre na rede (teste de duplicidade)"
  fi
  cat > /etc/netplan/60-ipv6.yaml <<EOF
# Gerado por baseline v$VERSAO — IPv6 estático
network:
  version: 2
  ethernets:
    $IF:
      accept-ra: false
      addresses: ["$V6/64"]
      routes:
        - to: "::/0"
          via: "$V6_GW"
EOF
  chmod 600 /etc/netplan/60-ipv6.yaml
  if ! netplan generate; then
    rm -f /etc/netplan/60-ipv6.yaml
    [[ -f "$BK/netplan/60-ipv6.yaml" ]] && cp -a "$BK/netplan/60-ipv6.yaml" /etc/netplan/
    pare "netplan generate reprovou /etc/netplan/60-ipv6.yaml (desfeito)"
  fi
  ok "/etc/netplan/60-ipv6.yaml gravado (rota padrão IPv6 vale após o reboot)"
else
  ok "IPv6: nada a fazer"
fi

# =================================================================================================
# 3. SSH + UFW (com volta automática)
# =================================================================================================
info "3/4 SSH e firewall"
# Volta automática: armada ANTES de mexer; restaura SSH e UFW como estavam se não houver confirmação.
cat > "$BK/volta.sh" <<EOF
#!/bin/bash
# Volta automática do baseline $TS — restaura SSH e UFW de antes
logger -t baseline "VOLTA AUTOMÁTICA: restaurando SSH e UFW (backup $BK)"
rm -f "$SSHD_ARQ"
cp -a "$BK/sshd_config.d/." /etc/ssh/sshd_config.d/ 2>/dev/null
cp -a "$BK/ufw/." /etc/ufw/ 2>/dev/null
if [ "$UFW_ANTES" = active ]; then ufw reload; else ufw --force disable; fi
if [ "$SOCKET_ANTES" = enabled ]; then
  systemctl disable ssh.service; systemctl enable ssh.socket; systemctl daemon-reload
  systemctl stop ssh.service; systemctl restart ssh.socket
else
  systemctl restart ssh.service
fi
EOF
chmod 700 "$BK/volta.sh"
VOLTA_UNIT="baseline-volta-$TS"
systemd-run --quiet --unit="$VOLTA_UNIT" --on-active="${VOLTA_MIN}min" /bin/bash "$BK/volta.sh" \
  || pare "Não consegui armar a volta automática (systemd-run) — nada foi alterado no SSH/UFW"
ok "Volta automática armada: $VOLTA_MIN min ($VOLTA_UNIT)"

install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$H/.ssh"
if [[ -n "$PUBKEY" ]] && ! grep -qF "$(awk '{print $2}' <<<"$PUBKEY")" "$AK" 2>/dev/null; then
  printf '%s\n' "$PUBKEY" >> "$AK"; ok "Chave $NOVO_FP adicionada em $AK"
fi
chown "$ADMIN_USER:$ADMIN_USER" "$AK"; chmod 600 "$AK"
PUBKEY_FPS=$(ssh-keygen -lf "$AK" 2>/dev/null | awk '{print $2}' | tr '\n' ' '); PUBKEY_FPS=${PUBKEY_FPS% }

[[ -f "$SSHD_ANTIGO" ]] && mv "$SSHD_ANTIGO" "$BK/" && ok "Arquivo da v1 ($SSHD_ANTIGO) substituído (cópia em $BK)"
cat > "$SSHD_ARQ" <<EOF
# Gerado por baseline v$VERSAO em $(date '+%F %T') — não edite à mão; rode o baseline de novo
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
EOF
chmod 644 "$SSHD_ARQ"
install -d -m 0755 /run/sshd
if ! sshd -t; then
  bash "$BK/volta.sh"; systemctl stop "$VOLTA_UNIT.timer" 2>/dev/null
  pare "sshd -t reprovou a configuração — SSH e UFW restaurados"
fi
systemctl disable --now ssh.socket >/dev/null 2>&1
systemctl enable ssh.service >/dev/null 2>&1
systemctl restart ssh.service || { bash "$BK/volta.sh"; pare "ssh.service não reiniciou — restaurado"; }
ok "sshd na porta $SSH_PORT (sessões abertas continuam)"

# UFW: só as regras com o comentário "baseline:" são do baseline; as demais (ex.: DNS Admin) ficam.
ufw_limpar_baseline() {
  local n
  while n=$(ufw status numbered 2>/dev/null | awk -F'[][]' '/# baseline:/{gsub(/ /,"",$2); print $2}' | sort -n | tail -1); [[ -n "$n" ]]; do
    ufw --force delete "$n" >/dev/null || break
  done
}
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw_limpar_baseline
for r in $GESTAO_SSH; do ufw allow from "$r" to any port "$SSH_PORT" proto tcp comment 'baseline: SSH gestao' >/dev/null || aviso "UFW recusou $r"; done
if [[ "$SNMP" == sim ]]; then
  for r in $SNMP_ORIGENS; do ufw allow from "$r" to any port 161 proto udp comment 'baseline: SNMP' >/dev/null || aviso "UFW recusou $r"; done
fi
ufw --force enable >/dev/null && ok "UFW ativo: SSH de $(wc -w <<<"$GESTAO_SSH") origem(ns)$([[ $SNMP == sim ]] && echo ", SNMP de $(wc -w <<<"$SNMP_ORIGENS")")"
ABERTAS=$(ufw status 2>/dev/null | grep -E 'ALLOW( IN)? +Anywhere' | grep -v '# baseline:' || true)
[[ -n "$ABERTAS" ]] && { aviso "Regras abertas para qualquer origem (não são do baseline; mantidas):"; echo "$ABERTAS" | sed 's/^/      /'; }

echo
echo -e "\e[1;33m  CONFIRMAÇÃO OBRIGATÓRIA — não feche esta janela.\e[0m"
echo "  Abra uma conexão SSH NOVA:  $ADMIN_USER@$V4  porta $SSH_PORT  (com a chave)"
echo "  Conseguiu entrar? Digite OK. Sem OK em $VOLTA_MIN min, SSH e UFW voltam ao que eram."
CONF=""
read -t $(( VOLTA_MIN * 60 - 20 )) -rp "  > " CONF </dev/tty || true
if [[ "${CONF^^}" == OK ]]; then
  systemctl stop "$VOLTA_UNIT.timer" 2>/dev/null; systemctl reset-failed "$VOLTA_UNIT" 2>/dev/null
  ok "Acesso confirmado — volta automática desarmada"
else
  echo "  Sem confirmação: aplicando a volta AGORA."
  systemctl stop "$VOLTA_UNIT.timer" 2>/dev/null; bash "$BK/volta.sh"
  pare "SSH e UFW restaurados. Confira chave, porta e lista de gestão e rode de novo. (Sistema e IPv6 já aplicados.)"
fi

# =================================================================================================
# 4. SNMPv3
# =================================================================================================
info "4/4 SNMPv3"
if [[ "$SNMP" == sim ]]; then
  cat > /etc/snmp/snmpd.conf <<EOF
# Gerado por baseline v$VERSAO em $(date '+%F %T') — somente SNMPv3 (authPriv), leitura
agentaddress udp:$V4:161,udp:127.0.0.1:161
sysLocation "$SNMP_LOCATION"
sysContact $SNMP_CONTACT
rouser $SNMP_USER priv
EOF
  VAR=/var/lib/snmp/snmpd.conf
  if [[ "$SNMP_TROCA_SENHA" == sim ]]; then
    systemctl stop snmpd
    if [[ ! -f "$VAR" ]]; then   # o snmpd (usuário Debian-snmp) precisa gravar aqui para converter o createUser
      if getent passwd Debian-snmp >/dev/null; then install -o Debian-snmp -g Debian-snmp -m 600 /dev/null "$VAR"; else install -m 600 /dev/null "$VAR"; fi
    fi
    sed -i '/^usmUser/d;/^createUser/d' "$VAR"
    printf 'createUser %s SHA-256 "%s" AES "%s"\n' "$SNMP_USER" "$AUTH" "$PRIV" >> "$VAR"
  fi
  systemctl enable snmpd >/dev/null 2>&1
  systemctl restart snmpd && sleep 2
  if [[ -n "$AUTH" ]]; then
    # Teste real sem senha em argumento: snmp.conf temporário (0600) só para este snmpget
    T=$(mktemp -d)
    printf 'defVersion 3\ndefSecurityLevel authPriv\ndefSecurityName %s\ndefAuthType SHA-256\ndefAuthPassphrase %s\ndefPrivType AES\ndefPrivPassphrase %s\n' \
      "$SNMP_USER" "$AUTH" "$PRIV" > "$T/snmp.conf"
    if SNMPCONFPATH="$T" snmpget 127.0.0.1 1.3.6.1.2.1.1.3.0 >/dev/null 2>&1; then ok "snmpget SNMPv3 local respondeu"
    else aviso "snmpget local NÃO respondeu — confira com: sudo baseline-verify"; fi
    rm -rf "$T"
  fi
  unset AUTH PRIV
  NC=$(grep -c '^createUser' "$VAR" 2>/dev/null); NU=$(grep -c '^usmUser' "$VAR" 2>/dev/null)
  [[ "${NC:-0}" == 0 && "${NU:-0}" -ge 1 ]] && ok "Usuário $SNMP_USER ativo (createUser=${NC:-0} usmUser=${NU:-0})" \
    || aviso "Contagem inesperada em $VAR: createUser=${NC:-0} usmUser=${NU:-0}"
else
  ok "SNMP: não configurado"
fi

# =================================================================================================
# REGISTRO (sem senhas) e instalação dos comandos
# =================================================================================================
{
  echo "# Gerado por baseline v$VERSAO em $(date '+%F %T') — SEM senhas. Serve de padrão para a próxima execução"
  echo "# e de modelo (--respostas) para outro servidor (troque HOSTNAME_ e V6)."
  for k in BASELINE_VERSAO TZ_ HOSTNAME_ ATUALIZAR_AGORA HORA ATUALIZA_SEGURAR IF V4 V4_GW V6_ATIVAR V6_PREFIXO V6 V6_GW \
           ADMIN_USER PUBKEY_FPS SSH_PORT GESTAO_SSH SNMP SNMP_ORIGENS SNMP_USER SNMP_LOCATION SNMP_CONTACT; do
    case $k in BASELINE_VERSAO) v=$VERSAO;; *) v=${!k};; esac
    printf '%s="%s"\n' "$k" "$v"
  done
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

AQUI=$(dirname "$(readlink -f "$0")")
[[ "$(readlink -f "$0")" == /usr/local/sbin/baseline ]] || install -m 700 "$(readlink -f "$0")" /usr/local/sbin/baseline
if [[ -f "$AQUI/baseline-verify.sh" ]]; then install -m 700 "$AQUI/baseline-verify.sh" /usr/local/sbin/baseline-verify
  ok "Instalados: /usr/local/sbin/baseline e /usr/local/sbin/baseline-verify"
else
  aviso "baseline-verify.sh não está ao lado deste script — baixe-o para conferir depois"
fi

echo
echo "=============================================================="
echo " Concluído. Log: $LOG   Cópias: $BK"
echo " Respostas (sem senha): $ENV_FILE"
echo
echo " Próximos passos:  reboot   →   sudo baseline-verify"
echo "=============================================================="
