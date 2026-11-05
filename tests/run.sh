#!/usr/bin/env bash
# Testes do baseline (sem dependências além do bash, do coreutils e — para a parte do sshd — do openssh-server).
# Uso: bash tests/run.sh        Saída 0 = tudo passou.
# Os scripts são lidos com `source` SÓ aqui (guard: sem executar nada); o arquivo de respostas nunca é executado.
# Parte do sshd real (tests/integracao.sh) exige root: roda via sudo se possível. BASELINE_EXIGE_SSHD=1 (CI) torna o skip um erro.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
RAIZ=$PWD
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
N=0; FALHAS=0
t() { # t "descrição" comando...
  local d=$1; shift; N=$((N+1))
  if "$@" >"$TMP/saida" 2>&1; then echo "  ok    $d"; else echo "  FALHA $d"; sed 's/^/        | /' "$TMP/saida"; FALHAS=$((FALHAS+1)); fi
}
sec() { echo; echo "== $* =="; }

# ---- helpers que rodam em subshell, com o script lido por `source` ------------------------------
# $1 = código a executar depois do `source`; $2.. = argumentos posicionais do código ($1.. dentro dele)
no_baseline() { local c=$1; shift; CODIGO=$c bash -c 'set -uo pipefail; source "$1"; shift; eval "$CODIGO"' _ "$RAIZ/baseline.sh" "$@"; }
no_verify()   { local c=$1; shift; CODIGO=$c bash -c 'set -uo pipefail; source "$1"; shift; eval "$CODIGO"' _ "$RAIZ/baseline-verify.sh" "$@"; }

sec "Sintaxe e política"
t "bash -n baseline.sh"        bash -n baseline.sh
t "bash -n baseline-verify.sh" bash -n baseline-verify.sh
t "versão 2.1.0 no baseline.sh"  grep -q '^VERSAO="2.1.0"' baseline.sh
t "nunca \`source\` de arquivo de respostas/env (só leitura chave=valor)" bash -c '! grep -nE "^[[:space:]]*(source|\.)[[:space:]]+(\"?\$(ARQ_RESP|ENV_FILE|ENV_ANTIGO)|/root/)" baseline.sh baseline-verify.sh'
t "log nasce 600 (install) ANTES do exec/tee" bash -c '
  a=$(grep -n "install -m 600 -o root -g root /dev/null \"\$LOG\"" baseline.sh | head -1 | cut -d: -f1)
  b=$(grep -n "^exec > >(tee" baseline.sh | head -1 | cut -d: -f1)
  [[ -n $a && -n $b && $a -lt $b ]]'
t "comentário da chave não vai ao log (ssh-keygen -lf só via fps_mostrar/awk)" bash -c '! grep -nE "ssh-keygen -lf \"\$AK\" 2>/dev/null \| sed" baseline.sh'
t "senha SNMP nunca em argumento de comando (sem -A/-X em snmpget)" bash -c '! grep -nE "snmpget[^|]* -[AX] " baseline.sh baseline-verify.sh'

sec "ler_kv (nunca executa o arquivo)"
cat > "$TMP/resp.env" <<'EOT'
# comentário
TZ_="America/Sao_Paulo"
export HOSTNAME_=web01
SSH_USUARIOS="admin backup"
EVIL="$(touch PWNED)"
MAIS=`touch PWNED2`
chave-invalida=1
EOT
t "lê chave=valor, aspas e export"  no_baseline 'declare -A R=(); cd "$1"; ler_kv "$2" R; [[ ${R[TZ_]} == America/Sao_Paulo && ${R[HOSTNAME_]} == web01 && ${R[SSH_USUARIOS]} == "admin backup" ]]' "$TMP" "$TMP/resp.env"
t "não executou nada ($(printf '$(...)'), crase)"  bash -c '[[ ! -e "$1/PWNED" && ! -e "$1/PWNED2" && ! -e "$2/PWNED" ]]' _ "$TMP" "$RAIZ"

sec "Validadores novos"
t "faixa: LoginGraceTime 30 vale"       no_baseline 'val_grace 30 && [[ $VALOR == 30 ]]'
t "faixa: LoginGraceTime 4 e 601 não"   no_baseline '! val_grace 4 && ! val_grace 601 && ! val_grace abc && ! val_grace ""'
t "faixa: ClientAliveInterval 0..3600"  no_baseline 'val_alive_int 0 && val_alive_int 3600 && ! val_alive_int 3601 && ! val_alive_int -1'
t "faixa: ClientAliveCountMax 1..10"    no_baseline 'val_alive_max 2 && val_alive_max 10 && ! val_alive_max 0 && ! val_alive_max 11'
t "faixa: zeros à esquerda não viram octal" no_baseline 'val_grace 030 && [[ $VALOR == 30 ]]'
t "AllowUsers: só o admin"              no_baseline 'ADMIN_USER=daemon; val_usuarios daemon >/dev/null && [[ $VALOR == daemon ]]'
t "AllowUsers: lista com vírgula e duplicado" no_baseline 'ADMIN_USER=daemon; val_usuarios "daemon,nobody daemon" >/dev/null && [[ $VALOR == "daemon nobody" ]]'
t "AllowUsers: sem o admin é recusado"  no_baseline 'ADMIN_USER=daemon; ! val_usuarios nobody >/dev/null'
t "AllowUsers: root é recusado"         no_baseline 'ADMIN_USER=daemon; ! val_usuarios "daemon root" >/dev/null'
t "AllowUsers: padrão (*, ?, user@host) recusado" no_baseline 'ADMIN_USER=daemon; ! val_usuarios "daemon *" >/dev/null && ! val_usuarios "daemon n?body" >/dev/null && ! val_usuarios "daemon nobody@10.0.0.1" >/dev/null'
t "AllowUsers: * não expande para arquivos do diretório" bash -c 'cd "$1"; touch nobody; source "$2"; ADMIN_USER=daemon; ! val_usuarios "daemon *" >/dev/null' _ "$TMP" "$RAIZ/baseline.sh"
t "AllowUsers: usuário inexistente recusado" no_baseline 'ADMIN_USER=daemon; ! val_usuarios "daemon naoexiste-xyz" >/dev/null'
t "AllowUsers: lista vazia recusada"    no_baseline 'ADMIN_USER=daemon; ! val_usuarios "" >/dev/null'

sec "Geração do 10-baseline.conf"
PREPARA='SSH_PORT=44320; SSH_USUARIOS="admin backup"; SSH_TCP_FWD=nao; SSH_AGENT_FWD=nao; SSH_GRACE=30; SSH_ALIVE_INT=300; SSH_ALIVE_MAX=2'
t "contém as seis diretivas novas com os padrões seguros" no_baseline "$PREPARA; gerar_sshd_conf > \"$TMP/c.conf\"
  grep -qx 'AllowUsers admin backup' \"$TMP/c.conf\" && grep -qx 'AllowTcpForwarding no' \"$TMP/c.conf\" && grep -qx 'AllowAgentForwarding no' \"$TMP/c.conf\" &&
  grep -qx 'LoginGraceTime 30' \"$TMP/c.conf\" && grep -qx 'ClientAliveInterval 300' \"$TMP/c.conf\" && grep -qx 'ClientAliveCountMax 2' \"$TMP/c.conf\""
t "sim vira yes"                no_baseline "$PREPARA; SSH_TCP_FWD=sim; SSH_AGENT_FWD=sim; gerar_sshd_conf > \"$TMP/y.conf\"; grep -qx 'AllowTcpForwarding yes' \"$TMP/y.conf\" && grep -qx 'AllowAgentForwarding yes' \"$TMP/y.conf\""
t "mantém as diretivas da v2.0.0" no_baseline "$PREPARA; gerar_sshd_conf > \"$TMP/c.conf\"; for l in 'Port 44320' 'PermitRootLogin no' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PubkeyAuthentication yes' 'MaxAuthTries 3' 'X11Forwarding no'; do grep -qx \"\$l\" \"$TMP/c.conf\" || exit 1; done"

sec "Arquivo de respostas (--respostas) com as chaves novas"
t "valores válidos entram nas variáveis" no_baseline 'ADMIN_USER=daemon; declare -A RESP=([SSH_USUARIOS]="daemon,nobody" [SSH_GRACE]=45 [SSH_TCP_FWD]=sim [SSH_ALIVE_INT]=0 [SSH_ALIVE_MAX]=3)
  pergunta SSH_USUARIOS T "" "" "" val_usuarios >/dev/null; pergunta SSH_GRACE T "" "" "" val_grace >/dev/null; pergunta SSH_TCP_FWD T "" "" "" val_simnao >/dev/null
  pergunta SSH_ALIVE_INT T "" "" "" val_alive_int >/dev/null; pergunta SSH_ALIVE_MAX T "" "" "" val_alive_max >/dev/null
  [[ $SSH_USUARIOS == "daemon nobody" && $SSH_GRACE == 45 && $SSH_TCP_FWD == sim && $SSH_ALIVE_INT == 0 && $SSH_ALIVE_MAX == 3 ]]'
t "AllowUsers sem o admin no arquivo → aborta (nada é alterado)" no_baseline 'ADMIN_USER=daemon; declare -A RESP=([SSH_USUARIOS]="nobody"); ( pergunta SSH_USUARIOS T "" "" "" val_usuarios ) >/dev/null 2>&1; [[ $? -ne 0 ]]'
t "valor inválido no arquivo aborta e o log recebe só 40 caracteres dele" no_baseline 'LOG=/dev/null; v=$(printf "9%.0s" {1..300}); declare -A RESP=([SSH_GRACE]="$v"); saida=$( ( pergunta SSH_GRACE T "" "" "" val_grace ) 2>&1 ); rc=$?; [[ $rc -ne 0 && ${#saida} -lt 200 ]]'

sec "sshd_diverge (saída de sshd -T de exemplo)"
FIX_OK=$'port 44320\npermitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nmaxauthtries 3\nx11forwarding no\nallowtcpforwarding no\nallowagentforwarding no\nlogingracetime 30\nclientaliveinterval 300\nclientalivecountmax 2\nallowusers admin\nallowusers backup'
printf '%s\n' "$FIX_OK" > "$TMP/ok.txt"
sed 's/^allowtcpforwarding no/allowtcpforwarding yes/' "$TMP/ok.txt" > "$TMP/tcp.txt"
{ cat "$TMP/ok.txt"; echo 'allowusers intruso'; } > "$TMP/extra.txt"
grep -v 'allowusers backup' "$TMP/ok.txt" > "$TMP/falta.txt"
sed 's/^logingracetime 30/logingracetime 120/' "$TMP/ok.txt" > "$TMP/grace.txt"
D="$PREPARA"
t "confere quando tudo bate"                  no_baseline "$D; sshd_diverge < \"$TMP/ok.txt\""
t "detecta forwarding yes"                    no_baseline "$D; ! sshd_diverge < \"$TMP/tcp.txt\" >/dev/null"
t "detecta AllowUsers a mais"                 no_baseline "$D; ! sshd_diverge < \"$TMP/extra.txt\" >/dev/null"
t "detecta AllowUsers a menos"                no_baseline "$D; ! sshd_diverge < \"$TMP/falta.txt\" >/dev/null"
t "detecta LoginGraceTime diferente"          no_baseline "$D; ! sshd_diverge < \"$TMP/grace.txt\" >/dev/null"

sec "baseline-verify: itens novos pelo sshd -T efetivo"
VE='declare -A E=([SSH_TCP_FWD]=nao [SSH_AGENT_FWD]=nao [SSH_GRACE]=30 [SSH_ALIVE_INT]=300 [SSH_ALIVE_MAX]=2 [SSH_USUARIOS]="admin backup")'
conta() { echo "confere_ssh_efetivo \"\$(cat $1)\" >/dev/null; echo \"\$PASS \$FAIL \$AVISO\""; }
t "tudo certo: 6 OK, 0 FALHA"   no_verify "$VE; PASS=0; FAIL=0; AVISO=0; $(conta "$TMP/ok.txt") | grep -qx '6 0 0'"
t "forwarding yes → FALHA"       no_verify "$VE; PASS=0; FAIL=0; AVISO=0; $(conta "$TMP/tcp.txt") | grep -qx '5 1 0'"
t "AllowUsers a mais → FALHA"    no_verify "$VE; PASS=0; FAIL=0; AVISO=0; $(conta "$TMP/extra.txt") | grep -qx '5 1 0'"
t "AllowUsers a menos → FALHA"   no_verify "$VE; PASS=0; FAIL=0; AVISO=0; $(conta "$TMP/falta.txt") | grep -qx '5 1 0'"
t "grace diferente → FALHA"      no_verify "$VE; PASS=0; FAIL=0; AVISO=0; $(conta "$TMP/grace.txt") | grep -qx '5 1 0'"
t "env da v2.0.0 (sem chaves novas) → AVISO, nunca FALHA" no_verify 'declare -A E=([SSH_PORT]=44320); PASS=0; FAIL=0; AVISO=0; confere_ssh_efetivo "" >/dev/null; [[ $FAIL == 0 && $AVISO == 6 ]]'
touch -d '2020-01-01' "$TMP/x" 2>/dev/null
mkdir -p "$TMP/p"; : > "$TMP/p/fechado"; chmod 600 "$TMP/p/fechado"; : > "$TMP/p/aberto"; chmod 644 "$TMP/p/aberto"
t "so_root: 600 do próprio usuário"  bash -c 'source "$1"; [[ $(stat -c %U "$2") == root ]] && so_root "$2" || [[ $(id -u) != 0 ]]' _ "$RAIZ/baseline-verify.sh" "$TMP/p/fechado"
t "so_root: 644 é recusado"          bash -c 'source "$1"; ! so_root "$2"' _ "$RAIZ/baseline-verify.sh" "$TMP/p/aberto"

sec "/root/baseline.env: sem senha, 600, chaves novas"
t "salvar_env grava as chaves novas, nenhuma senha, modo 600" no_baseline "
  ENV_FILE=\"$TMP/b.env\"; VERSAO=2.1.0; $PREPARA; AUTH='SenhaAuth123'; PRIV='SenhaPriv456'; SENHA='SenhaX789'; SNMP_USER=u; salvar_env
  [[ \$(stat -c %a \"\$ENV_FILE\") == 600 ]] && grep -qx 'SSH_USUARIOS=\"admin backup\"' \"\$ENV_FILE\" && grep -qx 'SSH_TCP_FWD=\"nao\"' \"\$ENV_FILE\" &&
  grep -qx 'SSH_AGENT_FWD=\"nao\"' \"\$ENV_FILE\" && grep -qx 'SSH_GRACE=\"30\"' \"\$ENV_FILE\" && grep -qx 'SSH_ALIVE_INT=\"300\"' \"\$ENV_FILE\" && grep -qx 'SSH_ALIVE_MAX=\"2\"' \"\$ENV_FILE\" &&
  ! grep -qE 'SenhaAuth123|SenhaPriv456|SenhaX789|AUTH|PRIV|SENHA' \"\$ENV_FILE\""

sec "Prova do login no journal (unidade ssh.service; loopback não conta)"
mkdir -p "$TMP/bin"
cat > "$TMP/bin/journalctl" <<'EOT'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$STUB_ARGS"
cat "$STUB_LOG"
EOT
chmod +x "$TMP/bin/journalctl"
export STUB_ARGS="$TMP/args" STUB_LOG="$TMP/journal"
printf '%s\n' 'Accepted publickey for admin from 127.0.0.1 port 40000 ssh2: ED25519 SHA256:abc' 'Accepted publickey for admin from ::1 port 40001 ssh2: ED25519 SHA256:abc' 'Accepted publickey for admin from ::ffff:127.0.0.1 port 40002 ssh2: ED25519 SHA256:abc' > "$TMP/journal"
t "só loopback (autoteste) → NÃO conta" env PATH="$TMP/bin:$PATH" bash -c 'source "$1"; ADMIN_USER=admin; ! login_remoto_visto 1700000000' _ "$RAIZ/baseline.sh"
t "consulta a unidade ssh.service desde o instante do restart" bash -c 'grep -q -- "-u ssh.service" "$1" && grep -q -- "--since @1700000000" "$1"' _ "$TMP/args"
printf '%s\n' 'Accepted publickey for bob from 203.0.113.9 port 51234 ssh2: ED25519 SHA256:abc' 'Failed publickey for admin from 203.0.113.9 port 51235 ssh2' 'Accepted password for admin from 203.0.113.9 port 51236 ssh2' > "$TMP/journal"
t "outro usuário / falha / senha → NÃO conta" env PATH="$TMP/bin:$PATH" bash -c 'source "$1"; ADMIN_USER=admin; ! login_remoto_visto 1700000000' _ "$RAIZ/baseline.sh"
printf '%s\n' 'Accepted publickey for admin from 127.0.0.1 port 40000 ssh2: ED25519 SHA256:abc' 'Accepted publickey for admin from 203.0.113.9 port 51234 ssh2: ED25519 SHA256:abc' > "$TMP/journal"
t "admin por chave de IP externo → conta e informa o IP" env PATH="$TMP/bin:$PATH" bash -c 'source "$1"; ADMIN_USER=admin; login_remoto_visto 1700000000 && [[ $LOGIN_IP == 203.0.113.9 ]]' _ "$RAIZ/baseline.sh"
printf '%s\n' 'Accepted publickey for admin from 2001:db8::7 port 51234 ssh2: ED25519 SHA256:abc' > "$TMP/journal"
t "IPv6 externo → conta" env PATH="$TMP/bin:$PATH" bash -c 'source "$1"; ADMIN_USER=admin; login_remoto_visto 1 && [[ $LOGIN_IP == 2001:db8::7 ]]' _ "$RAIZ/baseline.sh"
: > "$TMP/journal"
t "journal vazio/indisponível → NÃO conta (cai no segundo OK)" env PATH="$TMP/bin:$PATH" bash -c 'source "$1"; ADMIN_USER=admin; ! login_remoto_visto 1' _ "$RAIZ/baseline.sh"

sec "Limpeza do authorized_keys e quebra de linha"
printf 'ssh-ed25519 AAAAchaveA usuario@pc' > "$TMP/ak"        # SEM \n final, como muita gente cola
t "anexar_linha não cola na última chave" no_baseline "anexar_linha \"$TMP/ak\" 'ssh-ed25519 AAAAchaveB x'; [[ \$(wc -l < \"$TMP/ak\") == 2 ]] && head -1 \"$TMP/ak\" | grep -qx 'ssh-ed25519 AAAAchaveA usuario@pc'"
t "remover_marcador_autoteste tira só a chave de autoteste" no_baseline "TS=T1; AK=\"$TMP/ak\"; anexar_linha \"\$AK\" 'restrict ssh-ed25519 AAAAteste baseline-selftest-T1'; remover_marcador_autoteste; ! grep -q selftest \"\$AK\" && grep -q AAAAchaveA \"\$AK\" && grep -q AAAAchaveB \"\$AK\""
t "corta() limita o valor repetido no log" no_baseline 'x=$(corta "$(printf "x%.0s" {1..200})"); (( ${#x} <= 44 )) && [[ $(corta curto) == curto ]]'
t "fps_mostrar não imprime o comentário" bash -c 'source "$1"; d=$(mktemp -d); ssh-keygen -q -t ed25519 -N "" -C "segredo@notebook" -f "$d/k"; out=$(fps_mostrar "$d/k.pub"); rm -rf "$d"; [[ -n $out && $out != *segredo* ]]' _ "$RAIZ/baseline.sh"

sec "Versão marcada: SHA256SUMS"
t "SHA256SUMS confere com os scripts (regenere: sha256sum baseline.sh baseline-verify.sh > SHA256SUMS)" sha256sum -c --quiet SHA256SUMS
t "texto da release traz os dois sha256" bash -c 'for f in baseline.sh baseline-verify.sh; do h=$(sha256sum "$f" | cut -d" " -f1); grep -q "$h" docs/release-v2.1.0.md || exit 1; done'
t "README aponta para v2.1.0" bash -c 'grep -q "v2.1.0/baseline.sh" README.md && ! grep -q "v2.0.0/baseline" README.md'

sec "sshd real (tests/integracao.sh)"
if command -v sshd >/dev/null 2>&1 && command -v ssh >/dev/null 2>&1; then
  SUDO=()
  if [[ $EUID -ne 0 ]]; then if sudo -n true 2>/dev/null; then SUDO=(sudo); else SUDO=(nope); fi; fi
  if [[ ${SUDO[0]:-} == nope ]]; then
    if [[ ${BASELINE_EXIGE_SSHD:-0} == 1 ]]; then N=$((N+1)); FALHAS=$((FALHAS+1)); echo "  FALHA sem root nem sudo para a parte do sshd"; else echo "  skip  sem root/sudo"; fi
  else
    N=$((N+1))
    if "${SUDO[@]+"${SUDO[@]}"}" bash tests/integracao.sh; then echo "  ok    integração com sshd real"; else echo "  FALHA integração com sshd real"; FALHAS=$((FALHAS+1)); fi
  fi
elif [[ ${BASELINE_EXIGE_SSHD:-0} == 1 ]]; then N=$((N+1)); FALHAS=$((FALHAS+1)); echo "  FALHA sshd/ssh ausentes (apt install openssh-server)"
else echo "  skip  sshd/ssh não instalados"; fi

echo
if (( FALHAS )); then echo "RESULTADO: $FALHAS de $N teste(s) FALHARAM"; exit 1; fi
echo "RESULTADO: $N teste(s) passaram"
