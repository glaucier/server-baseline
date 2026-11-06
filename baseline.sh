#!/usr/bin/env bash
# =============================================================================
# baseline.sh — padrão inicial para servidores Ubuntu 24.04 LTS
#
#   1. Sistema: disco (LVM), relógio, fuso horário, nome do servidor, atualização e atualização automática,
#      atalhos de terminal (alias) e Ubuntu Pro (opcionais)
#   2. IPv6 estático derivado do IPv4 (opcional)
#   3. SSH: porta própria, só chave, sem root, AllowUsers/forwarding/timeouts + firewall UFW (com VOLTA AUTOMÁTICA)
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

VERSAO="2.2.0"
ENV_FILE=/root/baseline.env
ENV_ANTIGO=/root/g2-baseline.env          # v1 (g2-baseline): lido como padrão, nunca alterado
TS=$(date +%Y%m%d-%H%M%S)
LOG=/root/baseline-$TS.log
BK=/root/baseline-backup-$TS
SSHD_PRINCIPAL=/etc/ssh/sshd_config
SSHD_ARQ=/etc/ssh/sshd_config.d/10-baseline.conf
SNMPD_ARQ=/etc/snmp/snmpd.conf
SNMPD_OUTRO=nao
SSHD_ANTIGO=/etc/ssh/sshd_config.d/10-g2-hardening.conf
VOLTA_MIN=5

# ---- Saída -------------------------------------------------------------------------------------
info() { echo -e "\n\e[1;36m==> $*\e[0m"; }
ok()   { echo -e "  \e[32m[OK]\e[0m $*"; }
aviso(){ echo -e "  \e[33m[AVISO]\e[0m $*"; }
PASTA_SCRIPT=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
pare() {
  echo -e "  \e[31m[ERRO]\e[0m $*"; echo "Abortado. Log: $LOG"
  # O baseline-verify só é instalado em /usr/local/sbin no fim (4/4): depois de abortar, o instalado é o da versão ANTERIOR.
  if [[ -f "$PASTA_SCRIPT/baseline-verify.sh" ]]; then
    echo "Para conferir com a versão nova: sudo bash $PASTA_SCRIPT/baseline-verify.sh   (o 'sudo baseline-verify' instalado pode ser o da versão anterior)"
  else
    echo "Para conferir com a versão nova: baixe o baseline-verify.sh da v$VERSAO e rode: sudo bash baseline-verify.sh   (o 'sudo baseline-verify' instalado pode ser o da versão anterior)"
  fi
  exit 1
}

ajuda() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Arquivo de respostas: o mesmo formato de /root/baseline.env (CHAVE="valor", uma por linha).
O /root/baseline.env de um servidor serve de modelo para o próximo (troque HOSTNAME_ e V6).
Chaves: TZ_ HOSTNAME_ ATUALIZAR_AGORA HORA ATUALIZA_SEGURAR DISCO_EXPANDIR ATALHOS PRO_ANEXAR V6_ATIVAR V6_BLOCO V6_PREFIXO V6 V6_GW
        ADMIN_USER PUBKEY SSH_PORT GESTAO_SSH SSH_USUARIOS SSH_TCP_FWD SSH_AGENT_FWD SSH_GRACE SSH_ALIVE_INT SSH_ALIVE_MAX
        SNMP SNMP_ORIGENS SNMP_USER SNMP_LOCATION SNMP_CONTACT
O token do Ubuntu Pro NUNCA vai para arquivo de respostas: é sempre digitado (sem eco).
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
import ipaddress, socket, sys
tipo, v = sys.argv[1], sys.argv[2].strip()
DOC = [ipaddress.ip_network(x) for x in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
def sem_doc(obj):                                # endereço de DOCUMENTAÇÃO (RFC 5737/3849) = o exemplo copiado
    n = obj if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else ipaddress.ip_network(obj)
    if any(n.version == d.version and n.overlaps(d) for d in DOC):
        print("    isso é um endereço de EXEMPLO (documentação), não de uma rede real — use o da sua rede", file=sys.stderr)
        sys.exit(1)
    return obj
try:
    if tipo == "ipv4":
        print(sem_doc(ipaddress.IPv4Address(v)))
    elif tipo == "ipv6":
        a = sem_doc(ipaddress.IPv6Address(v))
        if a.is_link_local or a.is_loopback or a.is_multicast or a.is_unspecified: sys.exit(1)
        print(a.compressed)
    elif tipo == "rede":                         # IP ou rede (v4/v6) para o UFW
        n = sem_doc(ipaddress.ip_network(v, strict=False))
        if n.prefixlen == 0: sys.exit(1)         # 0.0.0.0/0 não é "rede de gestão"
        print(n.network_address.compressed if n.num_addresses == 1 else n.with_prefixlen)
    elif tipo == "prefixo64":                    # aceita 2804:db8:100:1 ou …::/64
        t = v if "/" in v else v.rstrip(":") + "::/64"
        n = sem_doc(ipaddress.IPv6Network(t, strict=False))
        if n.prefixlen != 64:
            print("    o prefixo da rede dos servidores é um /64 (o /32 ou /48 é o BLOCO do provedor)", file=sys.stderr); sys.exit(1)
        print(n.with_prefixlen)
    elif tipo == "bloco":                        # bloco IPv6 do provedor (/16 a /64)
        n = sem_doc(ipaddress.IPv6Network(v, strict=False))
        if not 16 <= n.prefixlen <= 64: sys.exit(1)
        print(n.with_prefixlen)
    elif tipo == "dentro":                       # rede $2 está dentro do bloco $3?
        sys.exit(0 if ipaddress.ip_network(v).subnet_of(ipaddress.ip_network(sys.argv[3])) else 1)
    elif tipo == "vizinho":                      # IPv4 → nome (PTR) → AAAA global: "nome aaaa"
        socket.setdefaulttimeout(4)
        nome = socket.gethostbyaddr(v)[0]
        for f in socket.getaddrinfo(nome, None, socket.AF_INET6):
            a = ipaddress.IPv6Address(f[4][0].split("%")[0])
            if a.is_global and a.ipv4_mapped is None:
                print(nome, a.compressed); sys.exit(0)
        sys.exit(1)
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
except (ValueError, IndexError, OSError):
    sys.exit(1)
PY
}

val_ipv6()     { VALOR=$(py_rede ipv6 "$1"); }
val_bloco()    { VALOR=$(py_rede bloco "$1"); }
val_prefixo()  { # /64 e, se o bloco do provedor foi informado, dentro dele
  VALOR=$(py_rede prefixo64 "$1") || return 1
  [[ -z "${V6_BLOCO:-}" ]] && return 0
  py_rede dentro "$VALOR" "$V6_BLOCO" || { echo "    $VALOR não está dentro do bloco $V6_BLOCO"; return 1; }; }
val_hora()     { [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] && VALOR="$1"; }
val_porta()    { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )) && VALOR=$((10#$1)); }
val_tz()       { timedatectl list-timezones 2>/dev/null | grep -qxF -- "$1" && VALOR="$1"; }
val_hostname() { [[ "${1,,}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] && VALOR="${1,,}"; }
val_usuario()  { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && id "$1" >/dev/null 2>&1 && VALOR="$1"; }
val_simnao()   { case "${1,,}" in s|sim|y|yes) VALOR=sim;; n|nao|não|no) VALOR=nao;; *) return 1;; esac; }
val_faixa()    { # val_faixa VALOR MIN MAX — inteiro decimal dentro da faixa
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )) && VALOR=$((10#$1)); }
val_grace()      { val_faixa "$1" 5 600; }
val_alive_int()  { val_faixa "$1" 0 3600; }
val_alive_max()  { val_faixa "$1" 1 10; }
val_usuarios() { # lista de usuários do AllowUsers: nomes simples, existentes, sem root, COM o administrador
  local u lista="" tem_adm=0
  local -a arr
  IFS=' ,' read -ra arr <<<"$1"
  for u in "${arr[@]}"; do
    [[ -z "$u" ]] && continue
    [[ "$u" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "    \"$u\" não é um nome de usuário simples (sem *, ? nem usuario@host)"; return 1; }
    [[ "$u" == root ]] && { echo "    root não entra por SSH (PermitRootLogin no)"; return 1; }
    id "$u" >/dev/null 2>&1 || { echo "    o usuário \"$u\" não existe neste servidor"; return 1; }
    [[ " $lista " == *" $u "* ]] && continue
    lista+="${lista:+ }$u"
    [[ "$u" == "${ADMIN_USER:-}" ]] && tem_adm=1
  done
  (( tem_adm )) || { echo "    a lista precisa incluir o administrador (${ADMIN_USER:-?}); sem ele você se tranca fora"; return 1; }
  VALOR="$lista"; }
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
    pare "$var=\"$(corta "$r")\" do arquivo de respostas é inválido — $titulo"
  fi
  echo
  echo -e "\e[1m$titulo\e[0m"
  [[ -n "$expl" ]] && echo "$expl" | sed 's/^/  /'
  if [[ "$exemplo" == formato:* ]]; then echo "  Formato:${exemplo#formato:}"; elif [[ -n "$exemplo" ]]; then echo "  Exemplo: $exemplo"; fi
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

# lista_redes VAR "Título" "Explicação" "lista padrão" — um IP/rede por vez (ou vários de uma vez), Enter vazio conclui
lista_redes() {
  local var=$1 titulo=$2 expl=$3 padrao=$4 r n novo
  local -a lista=()
  if [[ -n "${RESP[$var]+x}" ]]; then
    val_redes "${RESP[$var]}" || pare "$var=\"$(corta "${RESP[$var]}")\" do arquivo de respostas é inválido — $titulo"
    printf -v "$var" '%s' "$VALOR"; echo "  $titulo: $VALOR   (arquivo de respostas)"; return 0
  fi
  for r in $padrao; do n=$(py_rede rede "$r" 2>/dev/null) && lista+=("$n"); done
  echo
  echo -e "\e[1m$titulo\e[0m"
  [[ -n "$expl" ]] && echo "$expl" | sed 's/^/  /'
  echo "  Digite UM IP ou rede e Enter; repita para adicionar outro (ou vários de uma vez, separados por espaço ou vírgula)."
  echo "  Formato: a.b.c.d (um host) ou a.b.c.0/24 (uma rede); IPv6 também vale. Enter vazio = concluir. 'limpar' = recomeçar."
  while :; do
    if (( ${#lista[@]} )); then echo "  Lista (${#lista[@]}): ${lista[*]}"; else echo "  Lista: (vazia)"; fi
    read -rp "  Adicionar: " r </dev/tty
    r=${r//,/ }
    if [[ -z "${r// /}" ]]; then (( ${#lista[@]} )) && break; echo "    Informe pelo menos um."; continue; fi
    if [[ "${r,,}" == limpar ]]; then lista=(); continue; fi
    for novo in $r; do
      if n=$(py_rede rede "$novo"); then
        if [[ " ${lista[*]} " == *" $n "* ]]; then echo "    $n já está na lista"; else lista+=("$n"); fi
      else
        echo "    \"$novo\" não é IP nem rede válida — ignorado"
      fi
    done
  done
  printf -v "$var" '%s' "${lista[*]}"
}

corta() { local s=$1; (( ${#s} > 40 )) && s="${s:0:40}…"; printf '%s' "$s"; }   # valor vindo de arquivo, curto, para o log

# Mostra as chaves de um authorized_keys SEM o comentário (user@notebook é dado pessoal e iria para o log)
fps_mostrar() { ssh-keygen -lf "$1" 2>/dev/null | awk '{print $1, $2, $NF}'; }

# Acrescenta uma linha a um arquivo garantindo a quebra de linha antes (senão cola na última chave)
anexar_linha() { [[ -s "$1" && -n "$(tail -c1 "$1")" ]] && echo >> "$1"; printf '%s\n' "$2" >> "$1"; }

yn() { [[ "$1" == sim ]] && echo yes || echo no; }

# Temporários (senhas do teste SNMP, chave do autoteste) e a chave de autoteste no authorized_keys: sempre limpos na saída
TMPS=()
remover_marcador_autoteste() {
  local t
  [[ -n "${AK:-}" && -f "$AK" ]] && grep -qF -- "baseline-selftest-$TS" "$AK" || return 0
  t=$(mktemp) && { grep -vF -- "baseline-selftest-$TS" "$AK" > "$t"; cat "$t" > "$AK"; rm -f "$t"; }
}
limpar_temp() { local d; for d in "${TMPS[@]:-}"; do [[ -n "$d" ]] && rm -rf -- "$d"; done; remover_marcador_autoteste; }

# ---- Outros arquivos do sshd que VENCEM o 10-baseline.conf (o sshd usa a 1.ª ocorrência) ----------------------------
# Lê a ORDEM REAL de leitura (sshd_config + Include, glob em ordem bytewise; o 10-baseline.conf entra no lugar em que o padrão o encaixa,
# mesmo que ainda não exista) e diz quem define cada diretiva.  NUNCA escreve em arquivo de outro produto.
#   py_ssh plano  PRINCIPAL NOSSO CAND SAIDA [IGNORAR..]   grava em SAIDA o sshd_config com os Include expandidos e CAND no lugar de NOSSO
#                                                           (retorno 3 = o sshd_config não inclui NOSSO: ele seria ignorado)
#   py_ssh dono   PRINCIPAL NOSSO CAND DIRETIVA [IGNORAR..] linhas "arquivo<TAB>linha<TAB>valor<TAB>ANTES|DEPOIS<TAB>0|1(Match)"
py_ssh() { python3 -I - "$@" <<'PY'
import fnmatch, glob, os, re, sys

def ler(caminho):
    try:
        with open(caminho, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return None

KV = re.compile(r"^([A-Za-z0-9]+)\s*(?:=\s*|\s+)(.*)$")

def kv(texto):
    t = texto.strip()
    if not t or t.startswith("#"):
        return None
    m = KV.match(t)
    return (m.group(1).lower(), m.group(2).strip()) if m else None

def includes(texto):
    r = kv(texto)
    return r[1].split() if r and r[0] == "include" else None

def expande(padrao, base, nosso, ignorar):
    if not os.path.isabs(padrao):
        padrao = os.path.join(base, padrao)
    achados = {f for f in glob.glob(padrao) if os.path.isfile(f)}
    if fnmatch.fnmatchcase(nosso, padrao):
        achados.add(nosso)
    return sorted(f for f in achados if f not in ignorar)

def percorre(caminho, base, nosso, cand, ignorar, prof=0):
    linhas = ler(cand if caminho == nosso else caminho)
    if linhas is None:
        return
    seg = []
    for num, texto in enumerate(linhas, 1):
        pads = includes(texto)
        if pads is not None and prof < 5:
            if seg:
                yield (caminho, seg)
                seg = []
            for pad in pads:
                for f in expande(pad, base, nosso, ignorar):
                    yield from percorre(f, base, nosso, cand, ignorar, prof + 1)
        else:
            seg.append((num, texto))
    if seg:
        yield (caminho, seg)

modo = sys.argv[1]
if modo == "plano":
    principal, nosso, cand, saida = sys.argv[2:6]
    ignorar = set(sys.argv[6:])
    base = os.path.dirname(principal)
    linhas = ler(principal)
    if linhas is None:
        sys.exit(2)
    out = []
    for texto in linhas:
        pads = includes(texto)
        if pads is None:
            out.append(texto)
            continue
        for pad in pads:
            for f in expande(pad, base, nosso, ignorar):
                out.append("Include " + (cand if f == nosso else f))
    with open(saida, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    incluiu = any(c == nosso for c, _ in percorre(principal, base, nosso, cand, ignorar))
    sys.exit(0 if incluiu else 3)
elif modo == "dono":
    principal, nosso, cand, diretiva = sys.argv[2:6]
    diretiva = diretiva.lower()
    ignorar = set(sys.argv[6:])
    base = os.path.dirname(principal)
    passou = False
    match = {}
    antes, outros = [], []
    for caminho, seg in percorre(principal, base, nosso, cand, ignorar):
        if caminho == nosso:
            passou = True
            continue
        for num, texto in seg:
            r = kv(texto)
            if not r:
                continue
            if r[0] == "match":
                match[caminho] = True
                continue
            if r[0] == diretiva:
                cond = match.get(caminho, False)
                reg = "%s\t%d\t%s\t%s\t%d" % (os.path.basename(caminho), num, r[1], "DEPOIS" if passou else "ANTES", 1 if cond else 0)
                (outros if (cond or passou) else antes).append(reg)
    for reg in antes + outros:
        print(reg)
else:
    sys.exit(2)
PY
}

# Portas: compara o CONJUNTO (sem repetição). "Port 44320" repetido em outro arquivo não muda nada (o sshd escuta uma vez).
# ssh_portas_dif ESCOLHIDA "EFETIVAS" -> retorno 1 e a explicação se houver porta A MAIS ou faltar a escolhida
ssh_portas_dif() {
  local esc=$1 ef p mais="" falta=""
  ef=$(tr ' ' '\n' <<<"$2" | sed '/^$/d' | sort -nu | tr '\n' ' '); ef=${ef% }
  for p in $ef; do [[ "$p" == "$esc" ]] || mais+="${mais:+ }$p"; done
  [[ " $ef " == *" $esc "* ]] || falta=$esc
  [[ -z "$mais$falta" ]] && return 0
  echo "${mais:+porta a mais: $mais}${mais:+${falta:+; }}${falta:+falta a escolhida: $falta}"
  return 1
}

# Nome canônico (como no sshd_config) de uma diretiva em minúsculas
ssh_nome() {
  case $1 in
    port) echo Port;; permitrootlogin) echo PermitRootLogin;; passwordauthentication) echo PasswordAuthentication;;
    kbdinteractiveauthentication) echo KbdInteractiveAuthentication;; pubkeyauthentication) echo PubkeyAuthentication;;
    maxauthtries) echo MaxAuthTries;; x11forwarding) echo X11Forwarding;; allowtcpforwarding) echo AllowTcpForwarding;;
    allowagentforwarding) echo AllowAgentForwarding;; allowusers) echo AllowUsers;; logingracetime) echo LoginGraceTime;;
    clientaliveinterval) echo ClientAliveInterval;; clientalivecountmax) echo ClientAliveCountMax;; *) echo "$1";;
  esac
}
# Valor ESCOLHIDO (real) é menos seguro que o ESCOLHIDO? ssh_menos_seguro DIRETIVA ESCOLHIDO EFETIVO
ssh_menos_seguro() {
  case $1 in
    passwordauthentication|kbdinteractiveauthentication|x11forwarding|allowagentforwarding|allowtcpforwarding|permitrootlogin)
      [[ "$2" == no && "$3" != no ]];;
    pubkeyauthentication) [[ "$2" == yes && "$3" != yes ]];;
    maxauthtries) [[ "$2" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ ]] && (( $3 > $2 ));;
    port|allowusers) return 0;;       # conjuntos: qualquer diferença (porta a mais, usuário a mais) é tratada como menos segura
    *) return 1;;
  esac
}
# conforto (só avisa) | parar (segurança, valor menos seguro) | restritivo (segurança, valor MAIS seguro: só avisa)
ssh_classe() {
  case $1 in
    logingracetime|clientaliveinterval|clientalivecountmax) echo conforto;;
    *) if ssh_menos_seguro "$1" "$2" "$3"; then echo parar; else echo restritivo; fi;;
  esac
}
# Quem define a diretiva $1 (NOME [+ "(dentro de um bloco Match)"]) ou texto de "não identifiquei"; $2 = arquivo candidato
ssh_quem() {
  local l n c
  IFS= read -r l < <(py_ssh dono "$SSHD_PRINCIPAL" "$SSHD_ARQ" "${2:-$SSHD_ARQ}" "$1" "$SSHD_ANTIGO")
  [[ -n "$l" ]] || { echo "outro arquivo (não identifiquei qual — veja: sshd -T)"; return 0; }
  IFS=$'\t' read -r n _ _ _ c <<<"$l"
  [[ "$c" == 1 ]] && n+=" (dentro de um bloco Match)"
  echo "$n"
}
# Todos os arquivos que definem a diretiva (separados por vírgula), para as cumulativas (Port, AllowUsers)
ssh_quem_todos() {
  local l n nomes=""
  while IFS= read -r l; do
    n=${l%%$'\t'*}; [[ ", $nomes, " == *", $n, "* ]] || nomes+="${nomes:+, }$n"
  done < <(py_ssh dono "$SSHD_PRINCIPAL" "$SSHD_ARQ" "${2:-$SSHD_ARQ}" "$1" "$SSHD_ANTIGO")
  echo "${nomes:-outro arquivo (não identifiquei qual)}"
}

# O que a configuração ESCOLHIDA escreve no 10-baseline.conf ("chave valor", minúsculas, como o sshd -T imprime)
sshd_escolhido() {
  printf '%s\n' "port $SSH_PORT" "permitrootlogin no" "passwordauthentication no" "kbdinteractiveauthentication no" \
    "pubkeyauthentication yes" "maxauthtries 3" "x11forwarding no" \
    "allowtcpforwarding $(yn "$SSH_TCP_FWD")" "allowagentforwarding $(yn "$SSH_AGENT_FWD")" \
    "logingracetime $SSH_GRACE" "clientaliveinterval $SSH_ALIVE_INT" "clientalivecountmax $SSH_ALIVE_MAX"
}
# O que o sshd tem de produzir de FATO: o escolhido, trocado pelo valor de quem vence (SSH_OVERRIDE, calculado por ssh_conflitos
# ANTES do resumo). Sem conflito, é igual ao escolhido. Diferença fora disso continua sendo erro.
declare -A SSH_OVERRIDE=()
sshd_pares() {
  local k v
  while read -r k v; do printf '%s %s\n' "$k" "${SSH_OVERRIDE[$k]:-$v}"; done < <(sshd_escolhido)
}

# stdin = saída do sshd -T; imprime o que diverge do escolhido; retorno 1 se divergir (AllowUsers: conjunto exato)
sshd_diverge() {
  local saida par falta=0 efet esp
  saida=$(cat)
  while IFS= read -r par; do
    grep -qxF -- "$par" <<<"$saida" || { echo "    esperado '$par' — efetivo: '$(grep -m1 "^${par%% *} " <<<"$saida")'"; falta=1; }
  done < <(sshd_pares)
  efet=$(awk '$1=="port"{print $2}' <<<"$saida" | sort -nu | tr '\n' ' ')
  [[ "$efet" == "$SSH_PORT " ]] || { echo "    portas efetivas: ${efet:-(nenhuma)}— esperado: $SSH_PORT"; falta=1; }
  efet=$(awk '$1=="allowusers"{print $2}' <<<"$saida" | sort | tr '\n' ' ')
  esp=$(tr ' ' '\n' <<<"$SSH_USUARIOS" | sort | tr '\n' ' ')
  [[ "$efet" == "$esp" ]] || { echo "    AllowUsers efetivo: ${efet:-(nenhum)}— esperado: $esp"; falta=1; }
  return "$falta"
}

# Conteúdo do /etc/ssh/sshd_config.d/10-baseline.conf (stdout)
gerar_sshd_conf() {
  echo "# Gerado por baseline v$VERSAO em $(date '+%F %T') — não edite à mão; rode o baseline de novo"
  echo "Port $SSH_PORT"
  echo "PermitRootLogin no"
  echo "PasswordAuthentication no"
  echo "KbdInteractiveAuthentication no"
  echo "PubkeyAuthentication yes"
  echo "MaxAuthTries 3"
  echo "X11Forwarding no"
  echo "AllowUsers $SSH_USUARIOS"
  echo "AllowTcpForwarding $(yn "$SSH_TCP_FWD")"
  echo "AllowAgentForwarding $(yn "$SSH_AGENT_FWD")"
  echo "LoginGraceTime $SSH_GRACE"
  echo "ClientAliveInterval $SSH_ALIVE_INT"
  echo "ClientAliveCountMax $SSH_ALIVE_MAX"
}

# ANTES do resumo: simula o sshd com o 10-baseline.conf CANDIDATO no lugar certo da ordem de leitura (sshd -T -f, sem aplicar nada) e
# compara com o escolhido. Preenche SSH_CONF_PARAR (segurança MENOS segura: parar), SSH_CONF_AVISO (conforto / mais restritivo: avisar
# e seguir) e SSH_OVERRIDE (o valor que vence, que o autoteste passa a esperar). Não escreve em arquivo de ninguém.
SSH_CONF_PARAR=(); SSH_CONF_AVISO=()
ssh_conflitos() {
  local cand plano real k want rv cls nome quem rc extras pdif
  SSH_CONF_PARAR=(); SSH_CONF_AVISO=(); SSH_OVERRIDE=()
  cand=$(mktemp) && plano=$(mktemp) || { SSH_CONF_AVISO+=("sem espaço para os temporários: conflitos de SSH só serão conferidos depois de aplicar"); return 0; }
  TMPS+=("$cand" "$plano")
  gerar_sshd_conf > "$cand"
  py_ssh plano "$SSHD_PRINCIPAL" "$SSHD_ARQ" "$cand" "$plano" "$SSHD_ANTIGO"; rc=$?
  if (( rc == 3 )); then
    SSH_CONF_PARAR+=("$SSHD_PRINCIPAL não inclui $SSHD_ARQ (falta 'Include /etc/ssh/sshd_config.d/*.conf'): o sshd IGNORARIA o 10-baseline.conf e nada do que você escolheu valeria")
    return 0
  fi
  (( rc == 0 )) || { SSH_CONF_AVISO+=("não consegui ler $SSHD_PRINCIPAL para prever o sshd efetivo: conferirei só depois de aplicar"); return 0; }
  real=$(sshd -T -f "$plano" -C "user=$ADMIN_USER,host=localhost,addr=127.0.0.1" 2>&1) \
    || { SSH_CONF_AVISO+=("não consegui simular o sshd (sshd -T: $(head -1 <<<"$real")): conferirei só depois de aplicar"); return 0; }
  while read -r k want; do
    nome=$(ssh_nome "$k")
    case $k in
      port)
        rv=$(awk '$1=="port"{print $2}' <<<"$real" | sort -nu | tr '\n' ' '); rv=${rv% }
        pdif=$(ssh_portas_dif "$want" "$rv") && continue
        SSH_CONF_PARAR+=("SSH $nome: escolhido $want, mas o sshd escutaria em: ${rv:-nenhuma} ($pdif; $(ssh_quem_todos "$k" "$cand") define Port; Port ACUMULA entre arquivos) — a porta/UFW do baseline não valeriam")
        ;;
      *)
        rv=$(awk -v k="$k" '$1==k{print $2; exit}' <<<"$real")
        [[ "$rv" == "$want" ]] && continue
        quem=$(ssh_quem "$k" "$cand"); cls=$(ssh_classe "$k" "$want" "$rv")
        if [[ "$cls" == parar ]]; then
          SSH_CONF_PARAR+=("SSH $nome: escolhido $want, mas $quem define $rv e VENCE (o sshd usa a 1.ª ocorrência) — valor MENOS seguro")
        else
          SSH_OVERRIDE[$k]=$rv
          SSH_CONF_AVISO+=("SSH $nome: escolhido $want, mas $quem define $rv e VENCE (o sshd usa a 1.ª ocorrência)$([[ "$cls" == restritivo ]] && echo ' — mais restritivo que o escolhido')")
        fi
        ;;
    esac
  done < <(sshd_escolhido)
  rv=$(awk '$1=="allowusers"{print $2}' <<<"$real" | sort | tr '\n' ' '); rv=${rv% }
  want=$(tr ' ' '\n' <<<"$SSH_USUARIOS" | sort | tr '\n' ' '); want=${want% }
  if [[ "$rv" != "$want" ]]; then
    extras=$(comm -13 <(tr ' ' '\n' <<<"$want") <(tr ' ' '\n' <<<"$rv") | tr '\n' ' ')
    SSH_CONF_PARAR+=("SSH AllowUsers: escolhido $SSH_USUARIOS, mas $(ssh_quem_todos allowusers "$cand") ${extras:+acrescenta ${extras% } }(AllowUsers ACUMULA entre arquivos): efetivo = ${rv:-ninguém} — acesso diferente do escolhido")
  fi
}

# ---- SNMP: o baseline NUNCA sobrescreve um snmpd.conf de outro produto (como no SSH) --------------------------------
# 0 = o snmpd.conf existe, tem conteúdo, NÃO foi gerado pelo baseline e NÃO é o arquivo original do pacote snmpd (md5 do dpkg)
snmpd_de_outro() {
  local md5 pk
  [[ -s "$SNMPD_ARQ" ]] || return 1
  head -1 "$SNMPD_ARQ" | grep -q '^# Gerado por baseline v' && return 1
  pk=$(dpkg-query -W -f='${Conffiles}\n' snmpd 2>/dev/null | awk -v f="$SNMPD_ARQ" '$1==f{print $2}')
  md5=$(md5sum "$SNMPD_ARQ" 2>/dev/null | awk '{print $1}')
  [[ -n "$pk" && "$pk" == "$md5" ]] && return 1
  return 0
}
# Grava o snmpd.conf do baseline. Retorno 1 (sem tocar em nada) se o que existe é de outro produto (SNMPD_OUTRO=sim,
# decidido ANTES de instalar pacotes: o apt cria um snmpd.conf de fábrica que não deve contar como "de outro produto").
snmpd_gravar_conf() {
  [[ "$SNMPD_OUTRO" == sim ]] && return 1
  cat > "$SNMPD_ARQ" <<EOF
# Gerado por baseline v$VERSAO em $(date '+%F %T') — somente SNMPv3 (authPriv), leitura
agentaddress udp:$V4:161,udp:127.0.0.1:161
sysLocation "$SNMP_LOCATION"
sysContact $SNMP_CONTACT
rouser $SNMP_USER priv
EOF
}

# Autoteste (depois do restart, antes de pedir o OK). Dois níveis:
#  1) sshd -T -C (efetivo, com Match) tem de bater com o escolhido;
#  2) login REAL do ADMIN_USER na porta nova, pelo loopback, com chave efêmera (restrita a 127.0.0.1/::1, só roda /bin/true),
#     host key fixada (sem confiar na primeira conexão). A chave sai do authorized_keys no trap e logo ao fim.
# Retorno 0 = passou; 1 = falhou (motivo no stdout).
autoteste_ssh() {
  local d efet pub f
  efet=$(sshd -T -C "user=$ADMIN_USER,host=localhost,addr=127.0.0.1" 2>&1) || { echo "    sshd -T falhou: $efet"; return 1; }
  efet=$(sshd_diverge <<<"$efet") || { echo "  A configuração efetiva do sshd diverge do escolhido:"; echo "$efet"; return 1; }
  command -v ssh >/dev/null || { echo "    cliente ssh ausente (apt install openssh-client)"; return 1; }
  d=$(mktemp -d) || return 1; TMPS+=("$d")
  ssh-keygen -q -t ed25519 -N '' -C "baseline-selftest-$TS" -f "$d/k" || { echo "    ssh-keygen falhou"; return 1; }
  pub=$(cat "$d/k.pub")
  for f in /etc/ssh/ssh_host_*_key.pub; do [[ -r "$f" ]] && printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$(cut -d' ' -f1,2 "$f")"; done > "$d/kh"
  anexar_linha "$AK" "from=\"127.0.0.1,::1\",restrict,command=\"/bin/true\" $pub"
  if timeout 30 ssh -F /dev/null -p "$SSH_PORT" -i "$d/k" -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no \
       -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$d/kh" -o GlobalKnownHostsFile=/dev/null \
       -o ConnectTimeout=10 -o LogLevel=ERROR "$ADMIN_USER@127.0.0.1" true >/dev/null 2>&1; then
    remover_marcador_autoteste; rm -rf -- "$d"; return 0
  fi
  remover_marcador_autoteste; rm -rf -- "$d"
  echo "    o login de $ADMIN_USER na porta $SSH_PORT (chave, loopback) foi recusado com as regras novas"
  echo "    (veja AllowUsers/AllowGroups/Match em /etc/ssh/sshd_config.d e: journalctl -u ssh.service -n 20)"
  return 1
}

# Houve login de $ADMIN_USER por chave, de IP que NÃO é loopback, depois do instante $1 (epoch)? O autoteste (loopback) não conta.
# Ubuntu 24.04: unidade ssh.service; o LogLevel padrão (INFO) registra "Accepted publickey for USER from IP port N".
login_remoto_visto() {
  local ip
  while read -r ip; do
    case "$ip" in ""|127.*|::1|::ffff:127.*) continue;; *) LOGIN_IP=$ip; return 0;; esac
  done < <(journalctl -u ssh.service --since "@$1" -o cat --no-pager 2>/dev/null \
           | awk -v u="$ADMIN_USER" '$1=="Accepted" && $2=="publickey" && $3=="for" && $4==u && $5=="from" {print $6}')
  return 1
}

# Descarta o que foi digitado durante etapas longas (ex.: Enter apertado durante o apt), para não virar resposta
limpar_teclado() { local _l; while read -r -t 0.2 -n 256 _l </dev/tty 2>/dev/null; do :; done; }

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

# Respostas SEM senha → /root/baseline.env (padrão da próxima execução e modelo para --respostas)
salvar_env() {
  local k v
  {
    echo "# Gerado por baseline v$VERSAO em $(date '+%F %T') — SEM senhas. Serve de padrão para a próxima execução"
    echo "# e de modelo (--respostas) para outro servidor (troque HOSTNAME_ e V6)."
    for k in BASELINE_VERSAO TZ_ HOSTNAME_ ATUALIZAR_AGORA HORA ATUALIZA_SEGURAR DISCO_EXPANDIR ATALHOS PRO_ANEXAR IF V4 V4_GW V6_ATIVAR V6_BLOCO V6_PREFIXO V6 V6_GW \
             ADMIN_USER PUBKEY_FPS SSH_PORT GESTAO_SSH SSH_USUARIOS SSH_TCP_FWD SSH_AGENT_FWD SSH_GRACE SSH_ALIVE_INT SSH_ALIVE_MAX \
             SNMP SNMP_ORIGENS SNMP_USER SNMP_LOCATION SNMP_CONTACT; do
      case $k in BASELINE_VERSAO) v=$VERSAO;; *) v=${!k:-};; esac
      printf '%s="%s"\n' "$k" "$v"
    done
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

# ---- Disco (LVM): o instalador deixa o LV da raiz menor que o disco --------------------------------
# Define DISCO_LV, DISCO_VG, DISCO_LIVRE (bytes). Retorno 0 só se a raiz está num LV e o VG tem > 1 GB livre.
disco_info() {
  local src livre
  DISCO_LV=""; DISCO_VG=""; DISCO_LIVRE=0
  src=$(findmnt -no SOURCE / 2>/dev/null) || return 1
  src=${src%%\[*}
  [[ -n "$src" ]] || return 1
  DISCO_VG=$(lvs --noheadings -o vg_name "$src" 2>/dev/null | tr -d '[:space:]') || return 1
  [[ -n "$DISCO_VG" ]] || return 1
  livre=$(vgs --noheadings --units b --nosuffix -o vg_free "$DISCO_VG" 2>/dev/null | tr -d '[:space:]') || return 1
  livre=${livre%%.*}
  [[ "$livre" =~ ^[0-9]+$ ]] || return 1
  DISCO_LIVRE=$livre; DISCO_LV=$src
  (( DISCO_LIVRE > 1073741824 ))
}
disco_gb() { awk -v b="$1" 'BEGIN{printf "%.1f", b/1073741824}'; }
expandir_disco() { lvextend -r -l +100%FREE "$DISCO_LV"; }

# ---- Relógio ----------------------------------------------------------------------------------
relogio_sincronizado() { [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == yes ]]; }
relogio_servico() { # serviço de hora ativo (o baseline NÃO troca um pelo outro)
  local u
  for u in systemd-timesyncd chrony chronyd; do systemctl is-active --quiet "$u" 2>/dev/null && { echo "$u"; return 0; }; done
  return 1
}
relogio_esperar() { # $1 = limite em s (60), $2 = passo em s (2); 0 = sincronizou
  local lim=${1:-60} passo=${2:-2} t=0
  while ! relogio_sincronizado; do (( t >= lim )) && return 1; sleep "$passo"; t=$((t+passo)); done
  return 0
}

# ---- Atalhos de terminal (alias) em /etc/bash.bashrc, UM bloco marcado, reescrito por inteiro -------
ATALHO_INI="# baseline: atalhos (início)"
ATALHO_FIM="# baseline: atalhos (fim)"
BASHRC_ARQ=/etc/bash.bashrc
ATALHOS_LINHAS=""
# "nome=comando nome2=comando com espaços": uma palavra nome= abre um atalho novo. Resultado em ATALHOS_LINHAS (uma "nome=comando" por linha).
atalhos_parse() {
  local -a w=(); local p c nome="" cmd="" vistos=" "
  ATALHOS_LINHAS=""
  [[ "$1" == *$'\n'* ]] && { echo "    use uma linha só"; return 1; }
  for c in ';' '|' '&' '`' '$' '(' ')' '<' '>' '\' '"' "'"; do
    [[ "$1" == *"$c"* ]] && { echo "    caractere não permitido no comando: $c   (proibidos: ; | & \` \$ ( ) < > \\ e aspas)"; return 1; }
  done
  read -ra w <<<"$1"
  [[ ${#w[@]} -gt 0 ]] || return 1
  for p in "${w[@]}" ""; do
    if [[ -z "$p" || "$p" =~ ^[a-z][a-z0-9_-]*= ]]; then
      if [[ -n "$nome" ]]; then
        [[ -n "$cmd" ]] || { echo "    o atalho \"$nome\" está sem comando"; return 1; }
        ATALHOS_LINHAS+="$nome=$cmd"$'\n'
      fi
      [[ -z "$p" ]] && break
      nome=${p%%=*}; cmd=${p#*=}
      [[ "$vistos" == *" $nome "* ]] && { echo "    o atalho \"$nome\" está repetido"; return 1; }
      vistos+="$nome "
    else
      [[ -n "$nome" ]] || { echo "    \"$p\": use nome=comando (nome: [a-z][a-z0-9_-]*)"; return 1; }
      cmd+="${cmd:+ }$p"
    fi
  done
  [[ -n "$ATALHOS_LINHAS" ]]
}
val_atalhos() { # nenhum / - / n = sem atalhos (remove o bloco)
  case "${1,,}" in nenhum|-|n|nao|não) VALOR=""; return 0;; esac
  atalhos_parse "$1" || return 1
  VALOR=${ATALHOS_LINHAS//$'\n'/ }; VALOR=${VALOR% }
}
atalhos_bloco() { # stdout = o bloco (nada se a lista é vazia)
  local l
  [[ -n "$1" ]] || return 0
  atalhos_parse "$1" >/dev/null || return 1
  printf '%s\n' "$ATALHO_INI"
  while IFS= read -r l; do [[ -n "$l" ]] && printf "alias %s='%s'\n" "${l%%=*}" "${l#*=}"; done <<<"$ATALHOS_LINHAS"
  printf '%s\n' "$ATALHO_FIM"
}
# gravar_atalhos LISTA [ARQUIVO]: tira o bloco antigo (e a linha em branco que o precede) e põe o novo no fim. Idempotente.
# Nunca toca ~/.bashrc de usuário e nunca usa `source`.
gravar_atalhos() {
  local arq=${2:-$BASHRC_ARQ} t ni nf bloco
  bloco=$(atalhos_bloco "$1") || return 1
  [[ -f "$arq" ]] || : > "$arq"
  ni=$(grep -cxF -- "$ATALHO_INI" "$arq"); nf=$(grep -cxF -- "$ATALHO_FIM" "$arq")
  { [[ "$ni" == "$nf" ]] && (( ni <= 1 )); } || { echo "    marcadores de atalhos inconsistentes em $arq — nada foi alterado"; return 1; }
  t=$(mktemp) || return 1
  awk -v ini="$ATALHO_INI" -v fim="$ATALHO_FIM" '
    dentro { if ($0 == fim) dentro = 0; next }
    $0 == ini { dentro = 1; held = 0; next }
    { if (held) { print ""; held = 0 }
      if ($0 == "") { held = 1; next }
      print }
    END { if (held) print "" }' "$arq" > "$t"
  if [[ -n "$bloco" ]]; then
    [[ -s "$t" && -n "$(tail -c1 "$t")" ]] && echo >> "$t"
    { echo; printf '%s\n' "$bloco"; } >> "$t"
  fi
  cat "$t" > "$arq"; rm -f "$t"
}

# ---- Ubuntu Pro: o token só existe em variável de shell, em arquivo 0600 temporário e na tela sem eco ------------
val_token_pro() { [[ "$1" =~ ^[A-Za-z0-9_.=-]{8,256}$ ]]; }
pro_anexado() { pro status --format json 2>/dev/null | python3 -I -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("attached") else 1)' 2>/dev/null; }
ler_token_pro() { # resultado em PRO_TOKEN; vazio = desistiu
  local t
  PRO_TOKEN=""
  while :; do
    read -rsp "  Token do Ubuntu Pro (não aparece na tela; Enter vazio desiste): " t </dev/tty; echo
    [[ -z "$t" ]] && return 1
    val_token_pro "$t" && { PRO_TOKEN=$t; return 0; }
    echo "    Formato inesperado (8 a 256 letras, números, . _ = -). Copie o token inteiro de https://ubuntu.com/pro"
  done
}
# pro attach --attach-config ARQUIVO(0600 em pasta 0700, apagado no fim e no trap): o token NUNCA vai em argumento nem sai na saída
anexar_pro() {
  local d f l rc
  d=$(mktemp -d) || return 1; TMPS+=("$d"); chmod 700 "$d"; f=$d/attach.yaml
  ( umask 077; printf 'token: "%s"\n' "$PRO_TOKEN" > "$f" ); chmod 600 "$f"
  pro attach --attach-config "$f" 2>&1 | while IFS= read -r l; do printf '%s\n' "${l//"$PRO_TOKEN"/***}"; done
  rc=${PIPESTATUS[0]}
  rm -rf -- "$d"; PRO_TOKEN=""
  return "$rc"
}

# Permite `source baseline.sh` nos testes (tests/run.sh): só as funções, nada é executado
[[ "${BASH_SOURCE[0]}" != "$0" ]] && return 0

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
# Log só do root, desde o primeiro byte (não depender do umask); logs/cópias de execuções antigas também ficam fechados
install -m 600 -o root -g root /dev/null "$LOG"
chmod 600 /root/baseline-*.log 2>/dev/null
for d in /root/baseline-backup-*/; do [[ -d "$d" ]] && chmod 700 "$d"; done
trap limpar_temp EXIT
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
for f in /root/baseline-backup-*/PENDENTE; do
  [[ -e "$f" ]] || continue
  aviso "Execução de $(basename "$(dirname "$f")" | sed 's/^baseline-backup-//') NUNCA foi confirmada (sem o OK). Se houve reboot antes do OK, a volta automática foi desarmada."
  echo "        O SSH/UFW atuais são os NOVOS, sem confirmação. Esta execução confirma de novo; para desfazer: sudo bash $(dirname "$f")/volta.sh"
done

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

# Disco: o instalador do Ubuntu com LVM deixa o LV da raiz menor que o disco. Só pergunta se há > 1 GB livre no VG.
DISCO_EXPANDIR=""
if disco_info; then
  pergunta DISCO_EXPANDIR "Usar todo o disco para o sistema?" \
"O LV da raiz ($DISCO_LV) é menor que o disco: sobram $(disco_gb "$DISCO_LIVRE") GB livres no grupo $DISCO_VG.
Sim: lvextend -r -l +100%FREE (cresce o LV e o sistema de arquivos, com o sistema ligado, sem reiniciar).
Responda n se esse espaço for para outro LV ou snapshot — encolher depois é trabalhoso." "s" "$(p DISCO_EXPANDIR sim)" val_simnao
fi

# Relógio: DNSSEC e certificados dependem da hora certa. Só LÊ e espera; NÃO troca timesyncd por chrony.
RELOGIO_SERVICO=$(relogio_servico || true); RELOGIO_AVISO=""
if relogio_sincronizado; then RELOGIO_ESTADO="sincronizado"
else
  echo; echo "  Relógio ainda não sincronizado — aguardando até 60 s…"
  if relogio_esperar 60 2; then RELOGIO_ESTADO="sincronizado"
  else
    RELOGIO_ESTADO="NÃO sincronizado"
    RELOGIO_AVISO="DNSSEC e certificados dependem da hora certa. Confira o serviço de hora (systemctl status systemd-timesyncd ou chrony) e a saída UDP 123 para a internet."
  fi
fi
if [[ -z "$RELOGIO_SERVICO" ]]; then
  RELOGIO_AVISO="${RELOGIO_AVISO:+$RELOGIO_AVISO }Nenhum serviço de hora ativo (systemd-timesyncd nem chrony): o baseline NÃO escolhe um por você."
fi

info "IPv6"
# Sugestão do /64, sem inventar: 1) prefixo anunciado pelo roteador (SLAAC); 2) vizinho da MESMA rede IPv4 com AAAA no DNS
# (servidores DNS configurados e o gateway: IPv4 → nome reverso → AAAA). Não há regra universal IPv4 → IPv6: é o plano do provedor.
V6_DETECTADO=""; V6_ORIGEM=""; VIZ_SUF=""
x=$(ip -6 -o addr show dev "$IF" scope global 2>/dev/null | awk '/dynamic/{print $4; exit}')
if [[ -n "$x" ]] && V6_DETECTADO=$(py_rede prefixo_de "${x%/*}" 2>/dev/null); then V6_ORIGEM="anúncio do roteador (SLAAC $x)"; fi
if [[ -z "$V6_DETECTADO" ]]; then
  for ip in $( { resolvectl dns "$IF" 2>/dev/null | sed 's/^[^:]*://'; echo "$V4_GW"; } | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u); do
    py_rede contem "$ip" "$V4_CIDR" || continue
    r=$(py_rede vizinho "$ip" 2>/dev/null) || continue
    if V6_DETECTADO=$(py_rede prefixo_de "${r#* }" 2>/dev/null); then
      V6_ORIGEM="${r% *} ($ip → ${r#* }), na mesma rede IPv4 deste servidor"
      [[ "${r#* }" == *"::${ip##*.}" ]] && VIZ_SUF=sim     # o vizinho segue a convenção ::<último octeto>
      break
    fi
  done
fi
V6_ANT=$(p V6)
pergunta V6_ATIVAR "Configurar IPv6 estático nesta interface?" \
"O endereço sugerido usa o último octeto do IPv4. Responda n se esta rede não tem IPv6." "" \
"$(p V6_ATIVAR "$( [[ -n "$V6_ANT$V6_DETECTADO" ]] && echo sim || echo nao )")" val_simnao
V6_TESTE=""
if [[ "$V6_ATIVAR" == sim ]]; then
  while :; do
    pergunta V6_BLOCO "Bloco IPv6 do provedor (opcional)" \
"O bloco recebido do registro (ex.: o /32 do seu ASN no registro.br). Serve para conferir que o /64 abaixo é seu.
Enter vazio = não conferir." "formato: xxxx:xxxx::/32" "$(p V6_BLOCO)" val_bloco sim
    # O DETECTADO (evidência da rede) vem antes da resposta anterior: uma resposta errada salva não pode virar o padrão para sempre
    PREF_ANT=$(p V6_PREFIXO); [[ -z "$PREF_ANT" && -n "$V6_ANT" ]] && PREF_ANT=$(py_rede prefixo_de "$V6_ANT")
    PREF_PADRAO=${V6_DETECTADO:-$PREF_ANT}
    EXP="O /64 da rede em que este servidor está (o mesmo do gateway IPv6) — NÃO é o bloco /32 inteiro."
    [[ -n "$V6_DETECTADO" ]] && EXP+=$'\n'"Detectado: $V6_DETECTADO — por $V6_ORIGEM."
    [[ -n "$PREF_ANT" && "$PREF_ANT" != "$PREF_PADRAO" ]] && EXP+=$'\n'"(Resposta anterior: $PREF_ANT — diferente do detectado; confira.)"
    pergunta V6_PREFIXO "Prefixo IPv6 /64 da rede dos servidores" "$EXP" "formato: xxxx:xxxx:xxxx:xxxx::/64" "$PREF_PADRAO" val_prefixo
    V6_SUG=$(py_rede deriva "$V6_PREFIXO" "$OCT") || V6_SUG=""
    [[ -n "$V6_ANT" && "$(py_rede prefixo_de "$V6_ANT")" == "$V6_PREFIXO" && "$(p HOSTNAME_)" == "$HOSTNAME_" ]] && V6_SUG=$V6_ANT
    EXP="Sugestão: o prefixo + o último octeto do IPv4 ($OCT), escrito igual."
    [[ "$VIZ_SUF" == sim ]] && EXP+=" É a mesma regra do vizinho detectado."
    pergunta V6 "IPv6 deste servidor" "$EXP" "" "$V6_SUG" val_ipv6
    if [[ "$(py_rede prefixo_de "$V6")" != "$V6_PREFIXO" ]]; then echo "    $V6 não está no prefixo $V6_PREFIXO"; [[ -n "${RESP[V6]+x}" ]] && pare "V6 fora do V6_PREFIXO no arquivo de respostas"; continue; fi
    GW_SUG=$(p V6_GW); [[ -z "$GW_SUG" || "$(py_rede prefixo_de "$GW_SUG" 2>/dev/null)" != "$V6_PREFIXO" ]] && GW_SUG=$(py_rede deriva "$V6_PREFIXO" 1)
    pergunta V6_GW "Gateway IPv6" "Normalmente o ::1 do prefixo." "" "$GW_SUG" val_ipv6
    # Teste real, ANTES do resumo: o endereço entra por instantes na interface (o kernel testa duplicidade — DAD) e o gateway
    # precisa responder. Depois o endereço sai de novo (se não estava). Pega prefixo/gateway errados antes de gravar.
    echo "  Testando $V6 (duplicidade) e o gateway $V6_GW…"
    JA=0; ip -6 addr show dev "$IF" | grep -qi " $V6/64" && JA=1
    RC=0
    if (( ! JA )); then
      ip -6 addr add "$V6/64" dev "$IF" 2>/dev/null; sleep 3
      if ip -6 addr show dev "$IF" | grep -i " $V6/64" | grep -q dadfailed; then RC=2; fi
    fi
    if (( RC == 0 )); then ping -6 -c3 -W2 -I "$IF" "$V6_GW" >/dev/null 2>&1 || RC=1; fi
    (( JA )) || ip -6 addr del "$V6/64" dev "$IF" 2>/dev/null
    case $RC in
      0) V6_TESTE="ok: endereço livre e gateway respondeu"; ok "$V6 livre e o gateway $V6_GW respondeu"; break;;
      2) V6_TESTE=""; echo -e "  \e[31m$V6 JÁ ESTÁ EM USO por outro equipamento desta rede (DAD).\e[0m";;
      1) V6_TESTE="AVISO: gateway não respondeu ao ping"; aviso "O gateway $V6_GW NÃO respondeu. Prefixo ou gateway errados? (ou o gateway não responde a ping)";;
    esac
    if [[ -n "${RESP[V6]+x}" ]]; then (( RC == 2 )) && pare "IPv6 do arquivo de respostas em uso por outro equipamento"; break; fi
    if (( RC == 1 )); then read -rp "  [c]orrigir, [s]eguir assim mesmo ou [n]ão configurar IPv6? (c/s/n) [c]: " r </dev/tty
    else read -rp "  [c]orrigir ou [n]ão configurar IPv6? (c/n) [c]: " r </dev/tty; fi
    case "${r,,}" in
      s) (( RC == 1 )) && break;;
      n) V6_ATIVAR=nao; break;;
    esac
    unset 'RESP[V6_BLOCO]' 'RESP[V6_PREFIXO]' 'RESP[V6]' 'RESP[V6_GW]'
    # Corrigir: o bloco digitado fica; prefixo, endereço e gateway voltam a ser sugeridos (detectado e derivados), não o que falhou
    PADRAO[V6_BLOCO]=$V6_BLOCO; PADRAO[V6_PREFIXO]=""; PADRAO[V6_GW]=""; V6_ANT=""   # correção: o que foi digitado vira o padrão
  done
fi
if [[ "$V6_ATIVAR" != sim ]]; then V6=""; V6_GW=""; V6_PREFIXO=""; V6_BLOCO=""; V6_TESTE=""; fi

info "Acesso SSH"
ADM_PADRAO=$(p ADMIN_USER)
if [[ -z "$ADM_PADRAO" ]]; then
  for c in "${SUDO_USER:-}" "$(logname 2>/dev/null)" "$(who -m 2>/dev/null | awk '{print $1}')"; do
    [[ -n "$c" && "$c" != root ]] && id "$c" >/dev/null 2>&1 && { ADM_PADRAO=$c; break; }
  done
  [[ -z "$ADM_PADRAO" ]] && ADM_PADRAO=$(getent group sudo | cut -d: -f4 | cut -d, -f1)
fi
pergunta ADMIN_USER "Usuário administrador (precisa existir e ter sudo)" "O usuário criado na instalação do Ubuntu (não use root)." "" "$ADM_PADRAO" val_usuario
[[ "$ADMIN_USER" == root ]] && pare "O administrador não pode ser root: o login de root por SSH será desligado."
id -nG "$ADMIN_USER" | grep -qw sudo || aviso "$ADMIN_USER não está no grupo sudo — sem ele, depois do baseline você não terá root (sem login de root por SSH)."
H=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
AK="$H/.ssh/authorized_keys"
FPS_ATUAIS=$(ssh-keygen -lf "$AK" 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
PUBKEY=""
if [[ -n "${RESP[PUBKEY]+x}" ]]; then
  PUBKEY=${RESP[PUBKEY]}
elif [[ -n "$FPS_ATUAIS" ]]; then
  echo; echo "  Chaves já autorizadas para $ADMIN_USER:"; fps_mostrar "$AK" | sed 's/^/    /'
  read -rp "  Adicionar outra chave pública? (s/N): " r </dev/tty; r=${r:-n}
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
lista_redes GESTAO_SSH "IPs/redes que podem acessar o SSH (gestão)" \
"Só estes passam no firewall para o SSH: o seu computador, a VPN de gestão, o servidor de backup…" "$(p GESTAO_SSH "$CLIENTE_SSH")"
if [[ -n "$CLIENTE_SSH" ]] && ! py_rede contem "$CLIENTE_SSH" $GESTAO_SSH; then
  aviso "Você está conectado de $CLIENTE_SSH, que NÃO está na lista de gestão."
  read -rp "  Incluir $CLIENTE_SSH na gestão? (S/n): " r </dev/tty
  [[ "${r,,}" =~ ^n ]] || GESTAO_SSH+=" $(py_rede rede "$CLIENTE_SSH")"
fi

info "Endurecimento do SSH"
if [[ -n "${RESP[SSH_USUARIOS]+x}" || -z "$(p SSH_USUARIOS)" ]]; then USU_PADRAO=$ADMIN_USER
else USU_PADRAO=$(p SSH_USUARIOS); [[ " $USU_PADRAO " == *" $ADMIN_USER "* ]] || USU_PADRAO="$ADMIN_USER $USU_PADRAO"; fi
pergunta SSH_USUARIOS "Quem pode entrar por SSH (AllowUsers)" \
"Só estes usuários logam por SSH, mesmo que existam outros com chave. O administrador ($ADMIN_USER) é obrigatório.
Contas de serviço que usam SSH (backup, rsync…) PERDEM o acesso se não estiverem na lista.
Aceita vários, separados por espaço ou vírgula; só nomes simples (sem *, ? nem usuario@host)." \
"$ADMIN_USER backup" "$USU_PADRAO" val_usuarios
for u in $SSH_USUARIOS; do
  [[ "$u" == "$ADMIN_USER" ]] && continue
  hu=$(getent passwd "$u" | cut -d: -f6)
  [[ -s "$hu/.ssh/authorized_keys" ]] || aviso "$u está liberado, mas não tem $hu/.ssh/authorized_keys — sem chave ele não entra (senha está desligada)."
done
pergunta SSH_TCP_FWD "Permitir encaminhamento de portas TCP (AllowTcpForwarding)?" \
"Não: bloqueia túneis (ssh -L/-R), ssh -J (salto por este servidor como bastion) e o VS Code Remote; sftp/scp continuam.
Atenção: quem tem shell consegue contornar; isto reduz a superfície, não é barreira forte. Responda s ou n." \
"n" "$(p SSH_TCP_FWD nao)" val_simnao
pergunta SSH_AGENT_FWD "Permitir encaminhamento do agente SSH (AllowAgentForwarding)?" \
"Não: quem entra aqui não consegue usar a SUA chave a partir deste servidor para pular para outro (ssh -A).
Se o servidor for comprometido, o agente encaminhado seria usado pelo invasor. Responda s ou n." \
"n" "$(p SSH_AGENT_FWD nao)" val_simnao
pergunta SSH_GRACE "Tempo para concluir o login (LoginGraceTime, segundos)" \
"Conexão que não autentica nesse prazo é derrubada (segura vagas contra varredura). Faixa 5–600." \
"30" "$(p SSH_GRACE 30)" val_grace
pergunta SSH_ALIVE_INT "Intervalo de verificação da conexão (ClientAliveInterval, segundos)" \
"A cada N s o servidor testa se o cliente responde. Derruba conexão MORTA (cabo, VPN caída), não sessão parada:
o cliente responde sozinho. 0 desliga a verificação. Faixa 0–3600." "300" "$(p SSH_ALIVE_INT 300)" val_alive_int
pergunta SSH_ALIVE_MAX "Falhas seguidas antes de derrubar (ClientAliveCountMax)" \
"Com 300 s e 2 falhas, uma conexão morta cai em cerca de 10 min. Faixa 1–10." "2" "$(p SSH_ALIVE_MAX 2)" val_alive_max

# Conflitos com arquivos de OUTROS produtos no sshd (o sshd usa a 1.ª ocorrência): detectados ANTES do resumo, sem alterar nada
ssh_conflitos
if (( ${#SSH_CONF_PARAR[@]} )); then
  echo; echo -e "  \e[1;31mO SSH escolhido NÃO valeria, porque outro arquivo vence com valor menos seguro:\e[0m"
  for x in "${SSH_CONF_PARAR[@]}"; do echo "    - $x"; done
  echo "  O baseline NUNCA edita nem move arquivo de outro produto: ajuste a diretiva no arquivo indicado (ou escolha outro valor) e rode de novo."
  pare "Nada foi alterado (conflito de SSH com outro arquivo)"
fi

info "Atalhos de terminal e Ubuntu Pro"
AT_PADRAO="r=reset"; [[ -n "${PADRAO[ATALHOS]+x}" ]] && AT_PADRAO=${PADRAO[ATALHOS]:-nenhum}
pergunta ATALHOS "Atalhos de terminal (alias) para TODOS os usuários, inclusive root?" \
"Gravados num bloco marcado em /etc/bash.bashrc (só shells interativos do bash); ~/.bashrc de usuário não é tocado.
Formato: nome=comando, vários separados por espaço (o comando pode ter espaços). Nome: [a-z][a-z0-9_-]*.
Proibidos no comando: ponto e vírgula, barra vertical, &, crase, $, parênteses, < >, barra invertida e aspas. 'nenhum' remove o bloco (e os atalhos)." \
"r=reset ll=ls -la" "$AT_PADRAO" val_atalhos sim

PRO_TOKEN=""; PRO_JA=nao
command -v pro >/dev/null && pro_anexado && PRO_JA=sim
if [[ "$PRO_JA" == sim ]]; then
  PRO_ANEXAR=sim; echo; echo "  Ubuntu Pro: este servidor já está anexado — nada a fazer."
else
  pergunta PRO_ANEXAR "Anexar ao Ubuntu Pro (Livepatch, ESM)?" \
"Livepatch aplica correções do kernel sem reiniciar; ESM estende as atualizações de segurança. Gratuito para uso pessoal
e pequeno (token em https://ubuntu.com/pro). O token é digitado sem eco, passado ao 'pro attach' por arquivo temporário 0600
e NUNCA vai para log, resumo, argumento de comando nem para o baseline.env." "s" "$(p PRO_ANEXAR nao)" val_simnao
  if [[ "$PRO_ANEXAR" == sim ]]; then
    ler_token_pro || { aviso "Sem token: Ubuntu Pro não será anexado."; PRO_ANEXAR=nao; }
  fi
fi

info "SNMP"
pergunta SNMP "Configurar SNMPv3 (monitoramento, ex.: PRTG, Zabbix, LibreNMS)?" "Somente leitura, com usuário e duas senhas; sem community v1/v2c." "s" "$(p SNMP sim)" val_simnao
AUTH=""; PRIV=""; SNMP_TROCA_SENHA=nao
if [[ "$SNMP" == sim ]]; then
  lista_redes SNMP_ORIGENS "IPs/redes do servidor de monitoramento" "Só estes consultam a porta 161/udp (ex.: o PRTG)." "$(p SNMP_ORIGENS)"
  pergunta SNMP_USER "Usuário SNMPv3" "O mesmo cadastrado no sensor do monitoramento." "" "$(p SNMP_USER)" val_texto
  pergunta SNMP_LOCATION "Localização (sysLocation)" "Onde o servidor está; aparece no monitoramento (sem espaço é mais seguro)." "Sala_Servidores" "$(p SNMP_LOCATION)" val_texto
  pergunta SNMP_CONTACT "Contato (sysContact)" "E-mail do responsável." "suporte@seudominio" "$(p SNMP_CONTACT)" val_texto
  snmpd_de_outro && SNMPD_OUTRO=sim     # ANTES de instalar pacotes (o apt cria um snmpd.conf de fábrica)
  if [[ "$SNMPD_OUTRO" == sim ]]; then
    echo; aviso "$SNMPD_ARQ é de outro produto (não começa com \"# Gerado por baseline v\"): o baseline NÃO o altera nem pede senhas. Só o usuário SNMPv3 é conferido (sudo baseline-verify); estas respostas ficam no baseline.env e nas regras do UFW."
  else
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
if [[ "$DISCO_EXPANDIR" == sim ]]; then echo "  Disco ..............: expandir $DISCO_LV com +$(disco_gb "$DISCO_LIVRE") GB livres do grupo $DISCO_VG (lvextend -r -l +100%FREE)"
elif [[ "$DISCO_EXPANDIR" == nao ]]; then echo "  Disco ..............: NÃO expandir ($(disco_gb "$DISCO_LIVRE") GB livres no grupo $DISCO_VG ficam sem uso)"
else echo "  Disco ..............: nada a fazer (sem LVM na raiz ou sem espaço livre no grupo)"; fi
echo "  Relógio ............: $RELOGIO_ESTADO (serviço: ${RELOGIO_SERVICO:-nenhum ativo})"
[[ -n "$RELOGIO_AVISO" ]] && aviso "Relógio: $RELOGIO_AVISO"
if [[ -n "$ATALHOS" ]]; then echo "  Atalhos de terminal : $ATALHOS   (todos os usuários, em $BASHRC_ARQ)"
else echo "  Atalhos de terminal : nenhum (o bloco do baseline, se existir, será removido)"; fi
if [[ "$PRO_JA" == sim ]]; then echo "  Ubuntu Pro .........: já anexado (nada a fazer)"
elif [[ "$PRO_ANEXAR" == sim ]]; then echo "  Ubuntu Pro .........: anexar: sim (token recebido; não é gravado em lugar nenhum)"
else echo "  Ubuntu Pro .........: anexar: não"; fi
if [[ -n "$V6" ]]; then echo "  IPv6 ...............: $V6/64  gateway $V6_GW  ($IF)${V6_BLOCO:+  bloco $V6_BLOCO}"; echo "                        teste: $V6_TESTE"; else echo "  IPv6 ...............: não configurar"; fi
echo "  SSH ................: porta $SSH_PORT, só chave, sem root, administrador $ADMIN_USER"
echo "  SSH AllowUsers .....: $SSH_USUARIOS"
echo "  SSH encaminhamento .: portas TCP=$SSH_TCP_FWD, agente=$SSH_AGENT_FWD"
echo "  SSH tempos .........: login ${SSH_GRACE}s; verificação a cada ${SSH_ALIVE_INT}s x ${SSH_ALIVE_MAX}"
for x in "${SSH_CONF_AVISO[@]}"; do aviso "$x"; done
[[ -n "$NOVO_FP" ]] && echo "  Chave nova .........: $NOVO_FP"
echo "  UFW (entrada) ......: negar tudo, exceto:"
echo "      SSH $SSH_PORT/tcp de: $GESTAO_SSH"
[[ "$SNMP" == sim ]] && echo "      SNMP 161/udp de: $SNMP_ORIGENS"
echo "      (estado atual do UFW: ${UFW_ANTES:-desconhecido}; regras de outros programas são mantidas)"
if [[ "$SNMP" == sim && "$SNMPD_OUTRO" == sim ]]; then
  aviso "snmpd.conf de outro produto — mantido; só o usuário SNMPv3 é conferido"
  echo "  SNMPv3 .............: usuário $SNMP_USER; $SNMPD_ARQ NÃO será alterado (porta 161 liberada no UFW para $SNMP_ORIGENS)"
elif [[ "$SNMP" == sim ]]; then
  echo "  SNMPv3 .............: usuário $SNMP_USER (authPriv SHA-256/AES), escuta $V4 e 127.0.0.1"
  echo "                        senhas: $([[ $SNMP_TROCA_SENHA == sim ]] && echo 'novas' || echo 'mantidas')"
fi
echo "  Proteção ...........: se o novo acesso SSH não for confirmado em $VOLTA_MIN min, SSH e UFW voltam sozinhos"
echo "                        (NÃO reinicie o servidor antes do OK: o reboot desarma a volta automática)"
echo "  Autoteste ..........: login real de $ADMIN_USER pela porta nova (loopback); se falhar, volta na hora"
echo "  Cópias .............: $BK"
limpar_teclado
read -rp "Aplicar? (s/N): " C </dev/tty
[[ "${C,,}" =~ ^s ]] || pare "Cancelado (nada foi alterado)"
PUBKEY_FPS=$(echo $FPS_ATUAIS $NOVO_FP | tr ' ' '\n' | sort -u | tr '\n' ' '); PUBKEY_FPS=${PUBKEY_FPS% }
salvar_env

mkdir -p "$BK"
cp -a /etc/ssh/sshd_config.d "$BK/sshd_config.d" 2>/dev/null
cp -a /etc/netplan "$BK/netplan" 2>/dev/null
cp -a /etc/ufw "$BK/ufw" 2>/dev/null
cp -a /etc/snmp/snmpd.conf "$BK/" 2>/dev/null
cp -a /etc/hosts /etc/hostname "$BK/" 2>/dev/null
cp -a "$BASHRC_ARQ" "$BK/bash.bashrc" 2>/dev/null

# =================================================================================================
# 1. SISTEMA
# =================================================================================================
info "1/4 Sistema"
if [[ "$DISCO_EXPANDIR" == sim ]]; then
  if expandir_disco; then ok "Disco: $DISCO_LV expandido (+100%FREE do grupo $DISCO_VG)"
  else aviso "lvextend falhou — o disco não foi expandido (nada mais foi alterado por isso). Faça à mão: lvextend -r -l +100%FREE $DISCO_LV"; fi
fi
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
PKGS=(unattended-upgrades ufw openssh-client)
[[ "$SNMP" == sim ]] && PKGS+=(snmpd snmp)
[[ "$PRO_ANEXAR" == sim && "$PRO_JA" != sim ]] && PKGS+=(ubuntu-pro-client)
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

if gravar_atalhos "$ATALHOS"; then ok "Atalhos de terminal: ${ATALHOS:-nenhum (bloco removido)}"
else aviso "Atalhos não gravados em $BASHRC_ARQ (veja a mensagem acima)"; fi
if [[ "$PRO_JA" != sim && "$PRO_ANEXAR" == sim ]]; then
  if anexar_pro; then ok "Ubuntu Pro anexado"; else aviso "pro attach falhou — confira o token em https://ubuntu.com/pro e rode: sudo pro attach (o baseline-verify avisa)"; fi
fi

# =================================================================================================
# 2. IPv6
# =================================================================================================
info "2/4 IPv6"
if [[ -n "$V6" ]]; then
  if [[ -n "$(p V6)" && "$(p V6)" != "$V6" ]] && ip -6 addr show dev "$IF" | grep -qi " $(p V6)/64"; then
    ip -6 addr del "$(p V6)/64" dev "$IF" 2>/dev/null && ok "IPv6 anterior $(p V6) retirado da interface"
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
  ok "/etc/netplan/60-ipv6.yaml gravado (vale também após o reboot)"
  ip -6 addr show dev "$IF" | grep -qi " $V6/64" || ip -6 addr add "$V6/64" dev "$IF" 2>/dev/null
  ip -6 route replace default via "$V6_GW" dev "$IF" 2>/dev/null && ok "IPv6 ativo agora: $V6, rota padrão via $V6_GW"
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
rm -f "$BK/PENDENTE"
EOF
chmod 700 "$BK/volta.sh"
VOLTA_UNIT="baseline-volta-$TS"
systemd-run --quiet --unit="$VOLTA_UNIT" --on-active="${VOLTA_MIN}min" /bin/bash "$BK/volta.sh" \
  || pare "Não consegui armar a volta automática (systemd-run) — nada foi alterado no SSH/UFW"
# Marcador: se o servidor reiniciar antes do OK o timer (temporário, vive em /run) some e o marcador fica;
# o baseline-verify e a próxima execução avisam "nunca confirmado".
cat > "$BK/PENDENTE" <<EOF
Execução $TS do baseline v$VERSAO armada em $(date '+%F %T') e AINDA NÃO confirmada (sem o OK).
Se este arquivo continua aí, ou a confirmação não ocorreu ou o servidor reiniciou antes dela (a volta automática some no reboot).
Confirmar: rode o baseline de novo (ou teste o acesso e rode: sudo baseline-verify).  Desfazer: sudo bash $BK/volta.sh
EOF
ok "Volta automática armada: $VOLTA_MIN min ($VOLTA_UNIT)"

install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$H/.ssh"
if [[ -n "$PUBKEY" ]] && ! grep -qF "$(awk '{print $2}' <<<"$PUBKEY")" "$AK" 2>/dev/null; then
  anexar_linha "$AK" "$PUBKEY"; ok "Chave $NOVO_FP adicionada em $AK"
fi
chown "$ADMIN_USER:$ADMIN_USER" "$AK"; chmod 600 "$AK"
PUBKEY_FPS=$(ssh-keygen -lf "$AK" 2>/dev/null | awk '{print $2}' | tr '\n' ' '); PUBKEY_FPS=${PUBKEY_FPS% }

[[ -f "$SSHD_ANTIGO" ]] && mv "$SSHD_ANTIGO" "$BK/" && ok "Arquivo da v1 ($SSHD_ANTIGO) substituído (cópia em $BK)"
gerar_sshd_conf > "$SSHD_ARQ"
chmod 644 "$SSHD_ARQ"
install -d -m 0755 /run/sshd
if ! sshd -t; then
  bash "$BK/volta.sh"; systemctl stop "$VOLTA_UNIT.timer" 2>/dev/null
  pare "sshd -t reprovou a configuração — SSH e UFW restaurados"
fi
T_SSH=$(date +%s)     # logins "Accepted" só contam depois deste instante
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
echo "  Autoteste: login real de $ADMIN_USER na porta $SSH_PORT com as regras novas…"
AT_OUT=$(mktemp); TMPS+=("$AT_OUT")     # saída em arquivo (não em $(...)): os temporários ficam registrados no trap
if autoteste_ssh > "$AT_OUT"; then
  ok "Autoteste passou: sshd efetivo confere e $ADMIN_USER entrou (chave, loopback, porta $SSH_PORT)"
else
  cat "$AT_OUT"
  systemctl stop "$VOLTA_UNIT.timer" 2>/dev/null; bash "$BK/volta.sh"
  pare "Autoteste do SSH falhou — SSH e UFW restaurados. Corrija e rode de novo. (Sistema e IPv6 já aplicados.)"
fi

echo
echo -e "\e[1;33m  CONFIRMAÇÃO OBRIGATÓRIA — não feche esta janela.\e[0m"
echo "  Abra uma conexão SSH NOVA:  $ADMIN_USER@$V4  porta $SSH_PORT  (com a chave, de um IP da lista de gestão)"
echo "  Conseguiu entrar? Digite OK. Sem OK em $VOLTA_MIN min, SSH e UFW voltam ao que eram."
echo "  Não entrou? Digite NAO para voltar agora.   NÃO reinicie o servidor antes do OK (o reboot desarma a volta)."
[[ "$SSH_TCP_FWD" == nao ]] && echo "  (Encaminhamento de portas desligado: ssh -L/-J por este servidor deixam de funcionar. É o esperado.)"
CONF=""; SEM_PROVA=0; LOGIN_IP=""; LIMITE=$(( $(date +%s) + VOLTA_MIN * 60 - 20 ))
limpar_teclado
while :; do
  RESTA=$(( LIMITE - $(date +%s) )); (( RESTA > 0 )) || { CONF=""; break; }
  read -t "$RESTA" -rp "  [OK/NAO] (${RESTA}s) > " CONF </dev/tty || { CONF=""; break; }
  case "${CONF^^}" in
    OK)
      if login_remoto_visto "$T_SSH"; then ok "Visto no journal: login de $ADMIN_USER por chave vindo de $LOGIN_IP"; break; fi
      if (( SEM_PROVA )); then aviso "Confirmado SEM prova no journal (segundo OK)."; break; fi
      SEM_PROVA=1
      aviso "Não vi nenhum login de $ADMIN_USER por chave, de IP fora do loopback, depois do restart do SSH (journalctl -u ssh.service)."
      echo "    O autoteste local não conta. Entre numa conexão NOVA e digite OK de novo — ou, se tem certeza de que entrou, digite OK outra vez para confirmar assim mesmo."
      ;;
    NAO|NÃO|N) CONF=NAO; break;;
    *) echo "    Digite OK (entrou pela porta $SSH_PORT) ou NAO (não entrou — volta agora).";;
  esac
done
if [[ "${CONF^^}" == OK ]]; then
  systemctl stop "$VOLTA_UNIT.timer" 2>/dev/null; systemctl reset-failed "$VOLTA_UNIT" 2>/dev/null
  rm -f /root/baseline-backup-*/PENDENTE      # esta confirmação vale também para execuções anteriores não confirmadas
  ok "Acesso confirmado — volta automática desarmada"
else
  [[ "$CONF" == NAO ]] && echo "  Você respondeu NAO: aplicando a volta AGORA." || echo "  Prazo esgotado sem OK: aplicando a volta AGORA."
  systemctl stop "$VOLTA_UNIT.timer" 2>/dev/null; bash "$BK/volta.sh"
  pare "SSH e UFW restaurados. Confira chave, porta e lista de gestão e rode de novo. (Sistema e IPv6 já aplicados.)"
fi

# =================================================================================================
# 4. SNMPv3
# =================================================================================================
info "4/4 SNMPv3"
if [[ "$SNMP" == sim ]]; then
  if ! snmpd_gravar_conf; then
    aviso "$SNMPD_ARQ de outro produto — mantido (não foi sobrescrito); só o usuário SNMPv3 é conferido: sudo baseline-verify"
  else
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
      T=$(mktemp -d); TMPS+=("$T")
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
  fi
else
  ok "SNMP: não configurado"
fi

# =================================================================================================
# REGISTRO (sem senhas) e instalação dos comandos
# =================================================================================================
salvar_env
chmod 600 "$LOG" "$ENV_FILE"; chmod 700 "$BK"

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
