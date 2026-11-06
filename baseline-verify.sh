#!/usr/bin/env bash
# =============================================================================
# baseline-verify.sh — confere o padrão aplicado pelo baseline.sh
# Uso: sudo baseline-verify        (ou sudo bash baseline-verify.sh)
# SÓ LEITURA: não altera nada. Saída 0 = tudo OK; 1 = alguma FALHA.
# Lê /root/baseline.env (respostas da última execução, sem senha) — sem executá-lo.
# =============================================================================
set -uo pipefail
VERIFY_VERSAO="2.2.0"      # a versão DESTE verify (BASELINE_VERSAO, no .env, é a de quem aplicou o padrão)
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
inf() { echo -e "  \e[36m[INFO]\e[0m  $*"; }
sim_yn() { [[ "$1" == sim ]] && echo yes || echo no; }

SSHD_PRINCIPAL=/etc/ssh/sshd_config
SSHD_ARQ=/etc/ssh/sshd_config.d/10-baseline.conf
SSHD_ANTIGO=/etc/ssh/sshd_config.d/10-g2-hardening.conf

# --- CÓPIA EXATA do bloco de baseline.sh (tests/run.sh confere que é idêntica) ---
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

# Confere UMA diretiva de valor único contra o ESCOLHIDO. Se o efetivo difere, diz QUEM vence:
#   conforto ou mais restritivo + dono identificado -> AVISO "outro arquivo vence"; segurança MENOS segura ou sem dono -> FALHA.
ssh_confere_valor() { # $1 diretiva (minúscula)  $2 escolhido  $3 saída do sshd -T
  local k=$1 want=$2 real quem
  real=$(awk -v k="$k" '$1==k{print $2; exit}' <<<"$3")
  if [[ "$real" == "$want" ]]; then chk "sshd efetivo: $k $want" true; return 0; fi
  quem=$(ssh_quem "$k")
  if [[ "$quem" == "outro arquivo"* ]]; then
    chk "sshd efetivo: $k esperado $want, efetivo ${real:-nenhum} (nenhum outro arquivo o define: o 10-baseline.conf foi editado?)" false
  elif [[ "$(ssh_classe "$k" "$want" "$real")" == parar ]]; then
    chk "sshd efetivo: $k esperado $want, efetivo $real — $quem VENCE com valor MENOS seguro" false
  else
    avs "sshd efetivo: $k — outro arquivo vence: $quem define $real (o baseline escolheu $want)" false
  fi
}
ssh_confere_portas() { # $1 porta escolhida  $2 saída do sshd -T  (conjunto SEM repetição: Port repetida com o mesmo valor é a mesma porta)
  local efet dif
  efet=$(awk '$1=="port"{print $2}' <<<"$2" | sort -nu | tr '\n' ' '); efet=${efet% }
  if dif=$(ssh_portas_dif "$1" "$efet"); then chk "sshd efetivo: port $1" true
  else chk "sshd efetivo: port esperado $1, efetivo ${efet:-nenhuma} ($dif; $(ssh_quem_todos port) define Port; Port acumula entre arquivos)" false; fi
}

# SSH efetivo (saída do `sshd -T -C user=…`, que respeita Match) contra o que o baseline registrou.
# Chaves ausentes (env da v2.0.0) viram AVISO, não FALHA. AllowUsers: conjunto EXATO (a diretiva acumula entre arquivos).
confere_ssh_efetivo() { # $1 = saída do sshd -T
  local T=$1 k v par esp efet quem
  for par in "SSH_TCP_FWD allowtcpforwarding" "SSH_AGENT_FWD allowagentforwarding"; do
    k=${par% *}; v=${par#* }
    if [[ -z "$(e "$k")" ]]; then avs "sshd efetivo: $v (não registrado: baseline anterior à v2.1.0 — rode o baseline de novo)" false; continue; fi
    ssh_confere_valor "$v" "$(sim_yn "$(e "$k")")" "$T"
  done
  for par in "SSH_GRACE logingracetime" "SSH_ALIVE_INT clientaliveinterval" "SSH_ALIVE_MAX clientalivecountmax"; do
    k=${par% *}; v=${par#* }
    if [[ -z "$(e "$k")" ]]; then avs "sshd efetivo: $v (não registrado: baseline anterior à v2.1.0 — rode o baseline de novo)" false; continue; fi
    ssh_confere_valor "$v" "$(e "$k")" "$T"
  done
  if [[ -z "$(e SSH_USUARIOS)" ]]; then
    avs "sshd efetivo: allowusers (não registrado: baseline anterior à v2.1.0 — rode o baseline de novo)" false
  else
    esp=$(tr ' ' '\n' <<<"$(e SSH_USUARIOS)" | sort | tr '\n' ' ')
    efet=$(awk '$1=="allowusers"{print $2}' <<<"$T" | sort | tr '\n' ' ')
    if [[ "$efet" == "$esp" ]]; then chk "sshd efetivo: allowusers = $(e SSH_USUARIOS) (sem usuário a mais nem a menos)" true
    else
      quem=$(ssh_quem_todos allowusers)
      efet=${efet% }
      chk "sshd efetivo: allowusers esperado $(e SSH_USUARIOS), efetivo ${efet:-nenhum} ($quem; AllowUsers acumula entre arquivos)" false
    fi
  fi
}

# --- Atalhos de terminal: CÓPIAS EXATAS de baseline.sh (tests/run.sh confere que são idênticas) ---
ATALHO_INI="# baseline: atalhos (início)"
ATALHO_FIM="# baseline: atalhos (fim)"
BASHRC_ARQ=/etc/bash.bashrc
ATALHOS_LINHAS=""
# "nome=comando nome2=comando com espaços" -> ATALHOS_LINHAS
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
# stdout = o bloco esperado (nada se a lista é vazia)
atalhos_bloco() { # stdout = o bloco (nada se a lista é vazia)
  local l
  [[ -n "$1" ]] || return 0
  atalhos_parse "$1" >/dev/null || return 1
  printf '%s\n' "$ATALHO_INI"
  while IFS= read -r l; do [[ -n "$l" ]] && printf "alias %s='%s'\n" "${l%%=*}" "${l#*=}"; done <<<"$ATALHOS_LINHAS"
  printf '%s\n' "$ATALHO_FIM"
}
# O bloco que está de fato no arquivo $1 (do marcador de início ao de fim)
atalhos_bloco_atual() { awk -v ini="$ATALHO_INI" -v fim="$ATALHO_FIM" '$0 == ini { d = 1 } d { print } $0 == fim { d = 0 }' "$1"; }
# Alias efetivo: `bash -ic 'alias NOME'` como root e como o administrador
alias_efetivo() { # $1 = nome, $2 = "root" | usuário
  if [[ "$2" == root ]]; then HOME=/root bash -ic "alias $1" 2>/dev/null
  else runuser -l "$2" -c "bash -ic 'alias $1'" 2>/dev/null; fi
}

# --- Disco e relógio ---
# "VG livre_em_bytes" do grupo do LV da raiz; falha se a raiz não está em LVM
vg_raiz_livre() {
  local src vg livre
  src=$(findmnt -no SOURCE / 2>/dev/null) || return 1
  src=${src%%\[*}
  vg=$(lvs --noheadings -o vg_name "$src" 2>/dev/null | tr -d '[:space:]'); [[ -n "$vg" ]] || return 1
  livre=$(vgs --noheadings --units b --nosuffix -o vg_free "$vg" 2>/dev/null | tr -d '[:space:]'); livre=${livre%%.*}
  [[ "$livre" =~ ^[0-9]+$ ]] || return 1
  echo "$vg $livre"
}
relogio_sincronizado() { [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == yes ]]; }
relogio_servico() {
  local u
  for u in systemd-timesyncd chrony chronyd; do systemctl is-active --quiet "$u" 2>/dev/null && { echo "$u"; return 0; }; done
  return 1
}
# Ubuntu Pro: "sim <serviços habilitados>" ou "nao"
pro_estado() {
  local j
  command -v pro >/dev/null || { echo ausente; return 0; }
  j=$(pro status --format json 2>/dev/null) || { echo nao; return 0; }
  python3 -I -c 'import json,sys
d = json.load(sys.stdin)
print("sim " + " ".join(s["name"] for s in d.get("services", []) if s.get("status") == "enabled") if d.get("attached") else "nao")' <<<"$j" 2>/dev/null || echo nao
}

# --- CÓPIA EXATA de baseline.sh (tests/run.sh confere que é idêntica) ---
SNMPD_ARQ=/etc/snmp/snmpd.conf
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

# --- Cabeçalho: a versão DESTE verify e a de quem aplicou o padrão ---
verify_cabecalho() {
  echo "=============================================================="
  echo " baseline-verify v$VERIFY_VERSAO — $(hostname) — $(date '+%F %T')"
  echo " uptime: $(uptime -p)   padrão aplicado pela v$(e BASELINE_VERSAO)"
  echo "=============================================================="
}

# --- SNMP ---
# Escuta em ENDEREÇO:161? $1 = saída de `ss -ulnH`, $2 = endereço. Imprime: exato | todos (0.0.0.0, [::] ou *: cobrem o endereço) | (nada)
snmp_cobre() {
  if awk -v a="$2:161" '$4 == a { f = 1 } END { exit !f }' <<<"$1"; then echo exato
  elif awk '$4 == "0.0.0.0:161" || $4 == "[::]:161" || $4 == "*:161" { f = 1 } END { exit !f }' <<<"$1"; then echo todos; fi
}
# Escuta, rouser e community (e, se o snmpd.conf é de OUTRO produto, endereço/localização/contato só como AVISO informativo)
conf_tem_linha() { grep -E "^[[:space:]]*$1[[:space:]]" "$SNMPD_ARQ" 2>/dev/null | grep -qF -- "$2"; }
confere_snmp_conf() { # $1 = saída de `ss -ulnH`  $2 = IPv4 deste servidor  $3 = usuário SNMPv3
  local ss=$1 v4=$2 su=$3 outro=nao ad modo
  snmpd_de_outro && outro=sim
  [[ $outro == sim ]] && inf "snmpd.conf é de outro produto (não começa com \"# Gerado por baseline v\"): endereço de escuta, localização e contato são só informativos; rouser, community e o usuário SNMPv3 continuam valendo"
  for ad in "$v4" 127.0.0.1; do
    [[ -n "$ad" ]] || continue
    modo=$(snmp_cobre "$ss" "$ad")
    case $modo in
      exato) chk "snmpd escutando em $ad:161" true;;
      todos) chk "snmpd escuta em todos os endereços (0.0.0.0/[::]:161) — inclui $ad:161" true;;
      *) if [[ $outro == sim ]]; then avs "snmpd não escuta em $ad:161 (snmpd.conf de outro produto: informativo)" false
         else chk "snmpd escutando em $ad:161" false; fi;;
    esac
  done
  chk "rouser $su priv"                               grep -qx "rouser $su priv" "$SNMPD_ARQ"
  chk "Sem community (v1/v2c)"                        bash -c "! grep -qiE '^\s*(rocommunity|rwcommunity|com2sec)' '$SNMPD_ARQ'"
  if [[ $outro == sim ]]; then
    [[ -n "$(e SNMP_LOCATION)" ]] && avs "sysLocation $(e SNMP_LOCATION) no snmpd.conf (informativo)" conf_tem_linha sysLocation "$(e SNMP_LOCATION)"
    [[ -n "$(e SNMP_CONTACT)" ]]  && avs "sysContact $(e SNMP_CONTACT) no snmpd.conf (informativo)"  conf_tem_linha sysContact  "$(e SNMP_CONTACT)"
  fi
  return 0
}

# --- Teste real do SNMPv3 ---
TMPV=()
limpa_v() { local d; for d in "${TMPV[@]:-}"; do [[ -n "$d" ]] && rm -rf -- "$d"; done; }
# Leitura oculta: rótulo e quebra de linha na MESMA saída (stderr), e só QUANTOS caracteres foram digitados, nunca o conteúdo
ler_oculto() { # $1 = rótulo  $2 = nome da variável
  local _v
  printf '  %s' "$1" >&2
  read -rs _v
  printf '\n  (digitado: %d caracteres)\n' "${#_v}" >&2
  printf -v "$2" '%s' "$_v"
}
# Motivo legível do snmpget SEM senhas. $1 = stderr, $2/$3 = senhas (mascaradas se aparecerem)
snmp_motivo() {
  local e=$1 l
  case $e in
    *"Unknown user name"*)                                    echo "Unknown user name (usuário SNMPv3 errado ou inexistente)";;
    *"Decryption error"*)                                     echo "Decryption error (senha de CRIPTOGRAFIA)";;
    *"Authentication failure"*|*"wrong digest"*)              echo "Authentication failure / wrong digest (senha de AUTENTICAÇÃO)";;
    *Timeout*|*"No Response"*)                                echo "Timeout (rede, UFW ou endereço de escuta do snmpd)";;
    *) l=$(head -1 <<<"$e"); l=${l//"$2"/***}; l=${l//"$3"/***}; l=${l//\\/}; l=${l//[^[:print:]]/ }
       echo "motivo não reconhecido: ${l:-sem mensagem do snmpget}";;
  esac
}
# snmpget SNMPv3 em $1. Senhas SÓ em snmp.conf 0600 (pasta 0700, apagada no trap) apontado por SNMPCONFPATH — nunca no argv (ps).
# Retorno 0 = respondeu; senão 1 e SNMP_MOTIVO. $2 = usuário  $3 = senha de autenticação  $4 = senha de criptografia
SNMP_MOTIVO=""
snmp_get() {
  local d err
  SNMP_MOTIVO=""
  d=$(mktemp -d) || { SNMP_MOTIVO="sem espaço para o arquivo temporário"; return 1; }
  TMPV+=("$d"); chmod 700 "$d"
  ( umask 077; printf 'defVersion 3\ndefSecurityLevel authPriv\ndefSecurityName %s\ndefAuthType SHA-256\ndefAuthPassphrase %s\ndefPrivType AES\ndefPrivPassphrase %s\n' "$2" "$3" "$4" > "$d/snmp.conf" )
  chmod 600 "$d/snmp.conf"
  if err=$(SNMPCONFPATH="$d" snmpget -t 3 -r 1 "$1" 1.3.6.1.2.1.1.3.0 2>&1 >/dev/null); then rm -rf -- "$d"; return 0; fi
  rm -rf -- "$d"
  SNMP_MOTIVO=$(snmp_motivo "$err" "$3" "$4")
  return 1
}
# Testa em 127.0.0.1 E no IPv4 da interface; se só o local responde, diz que é o endereço de escuta/UFW
snmp_confere_real() { # $1 usuário  $2 senha de autenticação  $3 senha de criptografia  $4 IPv4
  local su=$1 a=$2 p=$3 v4=$4 okl=0 oki=0 ml="" mi=""
  snmp_get 127.0.0.1 "$su" "$a" "$p" && okl=1; ml=$SNMP_MOTIVO
  if [[ -n "$v4" ]]; then snmp_get "$v4" "$su" "$a" "$p" && oki=1; mi=$SNMP_MOTIVO; fi
  if (( okl )); then chk "snmpget SNMPv3 em 127.0.0.1 respondeu" true
  else chk "snmpget SNMPv3 em 127.0.0.1: $ml$( (( oki )) && echo ' (responde no IP, não no local)')" false; fi
  [[ -n "$v4" ]] || return 0
  if (( oki )); then chk "snmpget SNMPv3 em $v4 respondeu" true
  elif (( okl )); then chk "snmpget SNMPv3 em $v4: responde local, não no IP — confira o agentAddress e o UFW (motivo: $mi)" false
  else chk "snmpget SNMPv3 em $v4: $mi" false; fi
}

# Permissão: dono root e nenhum bit de grupo/outros. $1 = arquivo ou pasta
so_root() { local m o; m=$(stat -c '%a' "$1" 2>/dev/null) || return 1; o=$(stat -c '%U' "$1"); [[ "$o" == root ]] && (( (8#$m & 8#077) == 0 )); }

# Guard: `source baseline-verify.sh` nos testes (tests/run.sh) só traz as funções
[[ "${BASH_SOURCE[0]}" != "$0" ]] && return 0

trap limpa_v EXIT
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

verify_cabecalho

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

sec "Disco, relógio, atalhos e Ubuntu Pro"
if R=$(vg_raiz_livre); then
  VGN=${R% *}; VGL=${R#* }
  if (( VGL > 1073741824 )); then
    GBL=$(awk -v b="$VGL" 'BEGIN{printf "%.1f", b/1073741824}')
    ESC=""; [[ "$(e DISCO_EXPANDIR)" == nao ]] && ESC=" — você escolheu não expandir"
    echo -e "  \e[33m[AVISO]\e[0m Sobram $GBL GB livres no grupo $VGN da raiz (rode o baseline de novo e responda s em \"Usar todo o disco\", ou: lvextend -r -l +100%FREE <lv da raiz>)$ESC"
    AVISO=$((AVISO+1))
  else
    echo -e "  \e[32m[OK]\e[0m    Disco: ≤ 1 GB livre no grupo $VGN (LV da raiz ocupa o disco)"; PASS=$((PASS+1))
  fi
else
  inf "Disco: a raiz não está em LVM — nada a conferir"
fi
chk "Relógio sincronizado (NTPSynchronized=yes) — DNSSEC e certificados dependem da hora certa"  relogio_sincronizado
chk "Serviço de hora ativo ($(relogio_servico || echo 'nenhum: systemd-timesyncd ou chrony'))"   relogio_servico
if [[ -z "${E[ATALHOS]+x}" ]]; then
  avs "Atalhos de terminal (não registrado: baseline anterior à v2.2.0 — rode o baseline de novo)" false
else
  ESP_B=$(atalhos_bloco "$(e ATALHOS)")
  if [[ -z "$(e ATALHOS)" ]]; then
    chk "Sem bloco de atalhos em $BASHRC_ARQ (nenhum atalho escolhido)"   bash -c "! grep -qxF -- '$ATALHO_INI' '$BASHRC_ARQ'"
  else
    chk "Bloco de atalhos em $BASHRC_ARQ igual ao baseline.env"           igual "$(atalhos_bloco_atual "$BASHRC_ARQ")" "$ESP_B"
    chk "Um único bloco de atalhos"                                         bash -c "[[ \$(grep -cxF -- '$ATALHO_INI' '$BASHRC_ARQ') == 1 ]]"
    atalhos_parse "$(e ATALHOS)" >/dev/null
    while IFS= read -r al; do
      [[ -n "$al" ]] || continue
      for who in root "$ADMIN_USER"; do
        chk "Atalho '${al%%=*}' ativo para $who (bash -ic)"                igual "$(alias_efetivo "${al%%=*}" "$who")" "alias ${al%%=*}='${al#*=}'"
      done
    done <<<"$ATALHOS_LINHAS"
  fi
fi
PRO_E=$(pro_estado)
case "$PRO_E" in
  sim*) inf "Ubuntu Pro: anexado; serviços habilitados: ${PRO_E#sim }" ;;
  ausente) inf "Ubuntu Pro: comando 'pro' ausente" ;;
  *) inf "Ubuntu Pro: não anexado" ;;
esac
if [[ "$(e PRO_ANEXAR)" == sim && "$PRO_E" != sim* ]]; then
  echo -e "  \e[33m[AVISO]\e[0m Ubuntu Pro foi pedido no baseline mas NÃO está anexado (sudo pro attach — token em https://ubuntu.com/pro)"; AVISO=$((AVISO+1))
fi

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
ssh_confere_portas "$SSH_PORT" "$SSHD_T"
for par in "permitrootlogin no" "passwordauthentication no" "kbdinteractiveauthentication no" "pubkeyauthentication yes"; do
  ssh_confere_valor "${par% *}" "${par#* }" "$SSHD_T"
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
  confere_snmp_conf "$(ss -ulnH)" "$V4" "$SU"
  chk "Usuário criado (usmUser ≥ 1, createUser = 0)"  bash -c "(( \$(grep -c '^usmUser' /var/lib/snmp/snmpd.conf) >= 1 )) && (( \$(grep -c '^createUser' /var/lib/snmp/snmpd.conf) == 0 ))"
  if [[ -t 0 ]]; then
    echo; echo "  Teste real SNMPv3 (opcional). As senhas não aparecem na tela: só quantos caracteres foram digitados."
    ler_oculto "Senha de AUTENTICAÇÃO (Enter pula): " A
    if [[ -n "$A" ]]; then
      ler_oculto "Senha de CRIPTOGRAFIA: " P
      snmp_confere_real "$SU" "$A" "$P" "$V4"
      unset A P
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
