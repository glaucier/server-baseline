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
t "versão 2.2.0 no baseline.sh"  grep -q '^VERSAO="2.2.0"' baseline.sh
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
t "valor inválido no arquivo aborta e o log recebe só 40 caracteres dele" no_baseline 'LOG=/dev/null; v=$(printf "9%.0s" {1..300}); declare -A RESP=([SSH_GRACE]="$v"); saida=$( ( pergunta SSH_GRACE T "" "" "" val_grace ) 2>&1 ); rc=$?; [[ $rc -ne 0 && "$saida" != *"$(printf "9%.0s" {1..60})"* && "$saida" == *"$(printf "9%.0s" {1..40})…"* ]]'

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
VE='SSHD_PRINCIPAL=/nao/existe; declare -A E=([SSH_TCP_FWD]=nao [SSH_AGENT_FWD]=nao [SSH_GRACE]=30 [SSH_ALIVE_INT]=300 [SSH_ALIVE_MAX]=2 [SSH_USUARIOS]="admin backup")'
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
  ENV_FILE=\"$TMP/b.env\"; VERSAO=2.2.0; $PREPARA; AUTH='SenhaAuth123'; PRIV='SenhaPriv456'; SENHA='SenhaX789'; PRO_TOKEN='TokenPro1234567890'; DISCO_EXPANDIR=sim; ATALHOS='r=reset'; PRO_ANEXAR=sim; SNMP_USER=u; salvar_env
  [[ \$(stat -c %a \"\$ENV_FILE\") == 600 ]] && grep -qx 'SSH_USUARIOS=\"admin backup\"' \"\$ENV_FILE\" && grep -qx 'SSH_TCP_FWD=\"nao\"' \"\$ENV_FILE\" &&
  grep -qx 'SSH_AGENT_FWD=\"nao\"' \"\$ENV_FILE\" && grep -qx 'SSH_GRACE=\"30\"' \"\$ENV_FILE\" && grep -qx 'SSH_ALIVE_INT=\"300\"' \"\$ENV_FILE\" && grep -qx 'SSH_ALIVE_MAX=\"2\"' \"\$ENV_FILE\" &&
  ! grep -qE 'SenhaAuth123|SenhaPriv456|SenhaX789|TokenPro1234567890|AUTH|PRIV|SENHA|TOKEN' \"\$ENV_FILE\" && grep -qx 'DISCO_EXPANDIR=\"sim\"' \"\$ENV_FILE\" && grep -qx 'ATALHOS=\"r=reset\"' \"\$ENV_FILE\" && grep -qx 'PRO_ANEXAR=\"sim\"' \"\$ENV_FILE\""

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


sec "v2.2.0 — stubs de findmnt/lvs/vgs/lvextend/timedatectl/systemctl/sleep/pro"
ST="$TMP/stub"; mkdir -p "$ST"
cat > "$ST/findmnt" <<'EOT'
#!/usr/bin/env bash
echo "$STUB_SRC"
EOT
cat > "$ST/lvs" <<'EOT'
#!/usr/bin/env bash
last=""; for a in "$@"; do last=$a; done
[[ "$last" == "$STUB_LV" ]] && echo "  ${STUB_VG:-ubuntu-vg}" || exit 5
EOT
cat > "$ST/vgs" <<'EOT'
#!/usr/bin/env bash
echo "  $STUB_FREE"
EOT
cat > "$ST/lvextend" <<'EOT'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$STUB_LVX"
EOT
cat > "$ST/timedatectl" <<'EOT'
#!/usr/bin/env bash
n=$(cat "$STUB_CNT" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STUB_CNT"
if [[ "${STUB_SYNC_AFTER:-never}" != never ]] && (( n > STUB_SYNC_AFTER )); then echo yes; else echo no; fi
EOT
cat > "$ST/systemctl" <<'EOT'
#!/usr/bin/env bash
u=""; for a in "$@"; do u=$a; done
[[ " ${STUB_ACTIVE:-} " == *" $u "* ]]
EOT
cat > "$ST/sleep" <<'EOT'
#!/usr/bin/env bash
echo x >> "$STUB_SLEEP"
EOT
cat > "$ST/pro" <<'EOT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_PRO_ARGS"
case "$1" in
  status) echo "${STUB_PRO_JSON:-{\"attached\": false\}}";;
  attach)
    f=""; while (( $# )); do [[ "$1" == --attach-config ]] && { f=$2; shift; }; shift; done
    [[ -f "$f" ]] || exit 3
    cp "$f" "$STUB_PRO_SEEN"; stat -c %a "$f" > "$STUB_PRO_MODE"; echo "$f" > "$STUB_PRO_FILE"
    echo "Attaching with $(cut -d'"' -f2 "$f")"; echo "Account: exemplo"; exit "${STUB_PRO_RC:-0}";;
esac
EOT
chmod +x "$ST"/*
export STUB_SRC="/dev/mapper/ubuntu--vg-ubuntu--lv" STUB_LV="/dev/mapper/ubuntu--vg-ubuntu--lv" STUB_LVX="$TMP/lvx" STUB_CNT="$TMP/cnt" STUB_SLEEP="$TMP/slp" \
       STUB_PRO_ARGS="$TMP/pro.args" STUB_PRO_SEEN="$TMP/pro.seen" STUB_PRO_MODE="$TMP/pro.mode" STUB_PRO_FILE="$TMP/pro.file"
com() { PATH="$ST:$PATH" "$@"; }       # roda o comando com os stubs na frente do PATH
LVM_30G=32212254720

sec "1) Disco: espaço livre no VG da raiz → lvextend -r -l +100%FREE"
t "LVM com 30 GB livres → detecta LV, VG e espaço" env STUB_FREE=$LVM_30G PATH="$ST:$PATH" bash -c 'source "$1"; disco_info && [[ $DISCO_LV == /dev/mapper/ubuntu--vg-ubuntu--lv && $DISCO_VG == ubuntu-vg && $DISCO_LIVRE == 32212254720 && $(disco_gb "$DISCO_LIVRE") == 30.0 ]]' _ "$RAIZ/baseline.sh"
t "500 MB livres → nada a fazer (sem pergunta)"        env STUB_FREE=524288000 PATH="$ST:$PATH" bash -c 'source "$1"; ! disco_info' _ "$RAIZ/baseline.sh"
t "exatamente 1 GB → ainda nada (precisa de MAIS de 1 GB)" env STUB_FREE=1073741824 PATH="$ST:$PATH" bash -c 'source "$1"; ! disco_info' _ "$RAIZ/baseline.sh"
t "1 GB + 1 byte → pergunta"                            env STUB_FREE=1073741825 PATH="$ST:$PATH" bash -c 'source "$1"; disco_info' _ "$RAIZ/baseline.sh"
t "sem LVM (raiz em /dev/vda2) → nada a fazer"          env STUB_SRC=/dev/vda2 STUB_FREE=$LVM_30G PATH="$ST:$PATH" bash -c 'source "$1"; ! disco_info' _ "$RAIZ/baseline.sh"
t "raiz tipo /dev/mapper/x[/@] (subvolume) tem o sufixo removido" env STUB_SRC="/dev/mapper/ubuntu--vg-ubuntu--lv[/@]" STUB_FREE=$LVM_30G PATH="$ST:$PATH" bash -c 'source "$1"; disco_info && [[ $DISCO_LV == /dev/mapper/ubuntu--vg-ubuntu--lv ]]' _ "$RAIZ/baseline.sh"
t "expandir_disco chama exatamente: lvextend -r -l +100%FREE <lv da raiz>" env STUB_FREE=$LVM_30G PATH="$ST:$PATH" bash -c 'source "$1"; disco_info; expandir_disco; [[ $(cat "$STUB_LVX") == "-r -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv" ]]' _ "$RAIZ/baseline.sh"
t "a pergunta só existe dentro de \`if disco_info\` e o lvextend só com DISCO_EXPANDIR=sim" bash -c '
  grep -B2 "pergunta DISCO_EXPANDIR" baseline.sh | grep -q "if disco_info; then" && grep -B1 "if expandir_disco" baseline.sh | grep -q "DISCO_EXPANDIR\" == sim"'
t "resumo mostra o disco antes de Aplicar?" bash -c 'a=$(grep -n "Disco ..............: expandir" baseline.sh | head -1 | cut -d: -f1); b=$(grep -n "read -rp \"Aplicar" baseline.sh | cut -d: -f1); [[ -n $a && -n $b && $a -lt $b ]]'
t "verify: vg_raiz_livre acha o VG e os bytes"          env STUB_FREE=$LVM_30G PATH="$ST:$PATH" bash -c 'source "$1"; [[ $(vg_raiz_livre) == "ubuntu-vg 32212254720" ]]' _ "$RAIZ/baseline-verify.sh"
t "verify: raiz fora de LVM → sem checagem"             env STUB_SRC=/dev/vda2 STUB_FREE=$LVM_30G PATH="$ST:$PATH" bash -c 'source "$1"; ! vg_raiz_livre' _ "$RAIZ/baseline-verify.sh"
t "verify: AVISO (não FALHA) para > 1 GB livre"         bash -c 'grep -B1 -A4 "VGL > 1073741824" baseline-verify.sh | grep -q "AVISO"'

sec "2) Relógio: NTPSynchronized + serviço de hora; espera até 60 s; nunca troca de serviço"
rm -f "$STUB_CNT" "$STUB_SLEEP"
t "já sincronizado → não espera"                        env STUB_SYNC_AFTER=0 PATH="$ST:$PATH" bash -c 'source "$1"; relogio_esperar 60 2 && [[ ! -e "$STUB_SLEEP" ]]' _ "$RAIZ/baseline.sh"
rm -f "$STUB_CNT" "$STUB_SLEEP"
t "sincroniza depois de 3 leituras → espera e passa"    env STUB_SYNC_AFTER=3 PATH="$ST:$PATH" bash -c 'source "$1"; relogio_esperar 60 2 && [[ $(wc -l < "$STUB_SLEEP") == 3 ]]' _ "$RAIZ/baseline.sh"
rm -f "$STUB_CNT" "$STUB_SLEEP"
t "nunca sincroniza → espera 60 s (30 passos de 2 s) e desiste" env STUB_SYNC_AFTER=never PATH="$ST:$PATH" bash -c 'source "$1"; ! relogio_esperar 60 2 && [[ $(wc -l < "$STUB_SLEEP") == 30 ]]' _ "$RAIZ/baseline.sh"
t "serviço de hora: timesyncd"                          env STUB_ACTIVE="systemd-timesyncd" PATH="$ST:$PATH" bash -c 'source "$1"; [[ $(relogio_servico) == systemd-timesyncd ]]' _ "$RAIZ/baseline.sh"
t "serviço de hora: chrony"                             env STUB_ACTIVE="chrony" PATH="$ST:$PATH" bash -c 'source "$1"; [[ $(relogio_servico) == chrony ]]' _ "$RAIZ/baseline.sh"
t "nenhum serviço de hora ativo → falha"                env STUB_ACTIVE="" PATH="$ST:$PATH" bash -c 'source "$1"; ! relogio_servico' _ "$RAIZ/baseline.sh"
t "resumo traz o AVISO 'DNSSEC e certificados dependem da hora certa'" grep -q 'DNSSEC e certificados dependem da hora certa' baseline.sh
t "NÃO troca timesyncd por chrony (nem instala/para/mascara)" bash -c '! grep -nE "install[^#]*chrony|(disable|stop|mask|restart)[^#]*(timesyncd|chrony)" baseline.sh'
rm -f "$STUB_CNT"
t "verify: não sincronizado → FALHA"                    env STUB_SYNC_AFTER=never PATH="$ST:$PATH" bash -c 'source "$1"; PASS=0; FAIL=0; chk "relógio" relogio_sincronizado >/dev/null; [[ $FAIL == 1 ]]' _ "$RAIZ/baseline-verify.sh"
rm -f "$STUB_CNT"
t "verify: sincronizado → OK"                           env STUB_SYNC_AFTER=0 PATH="$ST:$PATH" bash -c 'source "$1"; PASS=0; FAIL=0; chk "relógio" relogio_sincronizado >/dev/null; [[ $PASS == 1 && $FAIL == 0 ]]' _ "$RAIZ/baseline-verify.sh"
t "verify: sem serviço de hora → FALHA"                 env STUB_ACTIVE="" PATH="$ST:$PATH" bash -c 'source "$1"; PASS=0; FAIL=0; chk "serviço" relogio_servico >/dev/null; [[ $FAIL == 1 ]]' _ "$RAIZ/baseline-verify.sh"

sec "3) Atalhos de terminal (bloco único em /etc/bash.bashrc)"
t "parse: um atalho"                                    no_baseline 'atalhos_parse "r=reset" && [[ $ATALHOS_LINHAS == "r=reset"$'"'"'\n'"'"' ]]'
t "parse: vários, comando com espaços"                  no_baseline 'atalhos_parse "r=reset ll=ls -la  l=ls -CF" && [[ $ATALHOS_LINHAS == "r=reset"$'"'"'\n'"'"'"ll=ls -la"$'"'"'\n'"'"'"l=ls -CF"$'"'"'\n'"'"' ]]'
for BAD in 'r=reset; rm -rf /' 'r=ls | wc' 'r=ls && id' 'r=`id`' 'r=$(id)' 'r=$HOME' 'r=(a)' 'r=ls > x' "r=echo 'oi'" 'r=echo "oi"' 'r=ls\x' 'R=reset' '1r=reset' 'r=' 'reset' 'r=reset r=ls' '-r=reset'; do
  t "recusa: $BAD" no_baseline '! val_atalhos "$1" >/dev/null' "$BAD"
done
t "recusa: duas linhas"                                 no_baseline '! val_atalhos "$1" >/dev/null' $'r=reset\nll=ls'
t "'nenhum' / '-' / n → lista vazia (remove o bloco)"  no_baseline 'val_atalhos nenhum && [[ -z $VALOR ]] && val_atalhos - && [[ -z $VALOR ]] && val_atalhos n && [[ -z $VALOR ]]'
t "padrão sugerido é r=reset"                           grep -q 'AT_PADRAO="r=reset"' baseline.sh
printf '# orig\n[ -z "$PS1" ] && return\nexport A=1\n' > "$TMP/rc.orig"
t "gravar: acrescenta UM bloco marcado no fim"          no_baseline 'cp "$1" "$2"; gravar_atalhos "r=reset ll=ls -la" "$2"
  [[ $(grep -cxF "$ATALHO_INI" "$2") == 1 && $(grep -cxF "$ATALHO_FIM" "$2") == 1 ]] && grep -qx "alias r='"'"'reset'"'"'" "$2" && grep -qx "alias ll='"'"'ls -la'"'"'" "$2" && head -3 "$2" | cmp -s - <(head -3 "$1")' "$TMP/rc.orig" "$TMP/rc.1"
t "rodar 2× não duplica o bloco (arquivo idêntico)"     no_baseline 'cp "$1" "$2"; gravar_atalhos "r=reset ll=ls -la" "$2"; cp "$2" "$2.1"; gravar_atalhos "r=reset ll=ls -la" "$2"; gravar_atalhos "r=reset ll=ls -la" "$2"
  cmp -s "$2" "$2.1" && [[ $(grep -cxF "$ATALHO_INI" "$2") == 1 && $(grep -c "^alias r=" "$2") == 1 ]]' "$TMP/rc.orig" "$TMP/rc.2"
t "trocar a lista reescreve o bloco inteiro (sem sobras)" no_baseline 'cp "$1" "$2"; gravar_atalhos "r=reset ll=ls -la" "$2"; gravar_atalhos "x=exit" "$2"
  [[ $(grep -cxF "$ATALHO_INI" "$2") == 1 ]] && grep -qx "alias x='"'"'exit'"'"'" "$2" && ! grep -q "alias r=\|alias ll=" "$2"' "$TMP/rc.orig" "$TMP/rc.3"
t "lista vazia remove o bloco e devolve o arquivo ao original" no_baseline 'cp "$1" "$2"; gravar_atalhos "r=reset" "$2"; gravar_atalhos "" "$2"; cmp -s "$1" "$2"' "$TMP/rc.orig" "$TMP/rc.4"
t "lista vazia num arquivo sem bloco não muda nada"     no_baseline 'cp "$1" "$2"; gravar_atalhos "" "$2"; cmp -s "$1" "$2"' "$TMP/rc.orig" "$TMP/rc.5"
printf '# orig sem quebra final' > "$TMP/rc.sem_nl"
t "arquivo sem quebra de linha final: não cola o bloco"  no_baseline 'cp "$1" "$2"; gravar_atalhos "r=reset" "$2"; head -1 "$2" | grep -qx "# orig sem quebra final" && [[ $(grep -cxF "$ATALHO_INI" "$2") == 1 ]]' "$TMP/rc.sem_nl" "$TMP/rc.6"
t "marcador de início sem o de fim → recusa e NÃO altera" no_baseline 'printf "x\n%s\nalias a=b\n" "$ATALHO_INI" > "$2"; cp "$2" "$2.bak"; ! gravar_atalhos "r=reset" "$2" >/dev/null && cmp -s "$2" "$2.bak"' "$TMP/rc.orig" "$TMP/rc.7"
t "conteúdo do usuário em volta do bloco é preservado"  no_baseline 'cp "$1" "$2"; gravar_atalhos "r=reset" "$2"; printf "export DEPOIS=1\n" >> "$2"; gravar_atalhos "r=reset ll=ls" "$2"; grep -qx "export A=1" "$2" && grep -qx "export DEPOIS=1" "$2" && [[ $(grep -cxF "$ATALHO_INI" "$2") == 1 ]]' "$TMP/rc.orig" "$TMP/rc.8"
t "o bash de verdade carrega os atalhos (bash -ic)"      no_baseline 'cp "$1" "$2"; gravar_atalhos "r=reset ll=ls -la" "$2"; [[ $(bash --rcfile "$2" -ic "alias r" 2>/dev/null) == "alias r='"'"'reset'"'"'" && $(bash --rcfile "$2" -ic "alias ll" 2>/dev/null) == "alias ll='"'"'ls -la'"'"'" ]]' "$TMP/rc.orig" "$TMP/rc.9"
mkdir -p "$TMP/home"; echo 'alias x=y' > "$TMP/home/.bashrc"; cp "$TMP/home/.bashrc" "$TMP/home/.bashrc.orig"
t "nunca toca ~/.bashrc de usuário"                      no_baseline 'HOME="$1"; cp "$2" "$3"; gravar_atalhos "r=reset" "$3"; cmp -s "$1/.bashrc" "$1/.bashrc.orig"' "$TMP/home" "$TMP/rc.orig" "$TMP/rc.10"
t "política: nenhuma escrita em ~/.bashrc de usuário; só /etc/bash.bashrc" bash -c '! grep -nE "^[^#]*((>>?|tee|sed -i|cp|mv|install)[^#]*)(~|\$H|\$HOME|/home/[^ ]*)/\.bashrc" baseline.sh && [[ $(grep -c "^BASHRC_ARQ=/etc/bash.bashrc" baseline.sh) == 1 ]]'
t "arquivo de respostas: ATALHOS válido, vazio e 'nenhum'" no_baseline 'declare -A RESP=([ATALHOS]="r=reset ll=ls -la"); pergunta ATALHOS T "" "" "" val_atalhos sim >/dev/null; [[ $ATALHOS == "r=reset ll=ls -la" ]]
  declare -A RESP=([ATALHOS]=""); pergunta ATALHOS T "" "" "r=reset" val_atalhos sim >/dev/null; [[ -z $ATALHOS ]]
  declare -A RESP=([ATALHOS]="nenhum"); pergunta ATALHOS T "" "" "r=reset" val_atalhos sim >/dev/null; [[ -z $ATALHOS ]]'
t "arquivo de respostas: ATALHOS perigoso aborta"        no_baseline 'LOG=/dev/null; declare -A RESP=([ATALHOS]="r=reset; id"); ( pergunta ATALHOS T "" "" "" val_atalhos sim ) >/dev/null 2>&1; [[ $? -ne 0 ]]'
t "verify: atalhos_parse/atalhos_bloco são cópias exatas das do baseline.sh" bash -c '
  a=$(source ./baseline.sh; declare -f atalhos_parse atalhos_bloco; echo "$ATALHO_INI|$ATALHO_FIM")
  b=$(source ./baseline-verify.sh; declare -f atalhos_parse atalhos_bloco; echo "$ATALHO_INI|$ATALHO_FIM")
  [[ -n $a && "$a" == "$b" ]]'
t "verify: bloco do arquivo = esperado → OK; bloco adulterado → difere" bash -c '
  f=$1; cp "$2" "$f"; ( source ./baseline.sh; gravar_atalhos "r=reset ll=ls -la" "$f" )
  source ./baseline-verify.sh
  [[ "$(atalhos_bloco_atual "$f")" == "$(atalhos_bloco "r=reset ll=ls -la")" ]] || exit 1
  sed -i "s/reset/halt/" "$f"
  [[ "$(atalhos_bloco_atual "$f")" != "$(atalhos_bloco "r=reset ll=ls -la")" ]]' _ "$TMP/rc.v" "$TMP/rc.orig"
t "verify: confere o alias efetivo como root e como o administrador (bash -ic)" bash -c 'grep -q "alias_efetivo \"\${al%%=\*}\" \"\$who\"" baseline-verify.sh && grep -q "for who in root \"\$ADMIN_USER\"" baseline-verify.sh'

sec "4) Ubuntu Pro: token nunca em argv, log, .env nem resumo"
TOK='TESTtoken1234567890ABCxyz'
rm -f "$STUB_PRO_ARGS" "$STUB_PRO_SEEN" "$STUB_PRO_MODE" "$STUB_PRO_FILE"
com bash -c 'source "$1"; PRO_TOKEN="$2"; anexar_pro; echo "rc=$? token_limpo=[${PRO_TOKEN}]"' _ "$RAIZ/baseline.sh" "$TOK" > "$TMP/pro.log" 2>&1
t "attach usa --attach-config ARQUIVO (token fora do argv)" bash -c 'grep -qx "attach --attach-config .*" "$1" && ! grep -qF -- "$2" "$1"' _ "$STUB_PRO_ARGS" "$TOK"
t "o arquivo temporário tinha o token e modo 600"        bash -c 'grep -qx "token: \"$2\"" "$1" && [[ $(cat "$3") == 600 ]]' _ "$STUB_PRO_SEEN" "$TOK" "$STUB_PRO_MODE"
t "o arquivo temporário (e a pasta) foram apagados"      bash -c 'f=$(cat "$1"); [[ -n $f && ! -e "$f" && ! -e "$(dirname "$f")" ]]' _ "$STUB_PRO_FILE"
t "token NÃO aparece no log (a saída do pro é mascarada)" bash -c '! grep -qF -- "$2" "$1" && grep -q "Attaching with \*\*\*" "$1" && grep -q "rc=0 token_limpo=\[\]" "$1"' _ "$TMP/pro.log" "$TOK"
rm -f "$STUB_PRO_ARGS" "$STUB_PRO_FILE"
cat > "$TMP/pro_falha.sh" <<'EOT'
source "$1"; PRO_TOKEN="$2"; anexar_pro; echo "rc=$?"
EOT
t "falha do pro: devolve o código, apaga o arquivo, sem token na saída" bash -c '
  out=$(STUB_PRO_RC=1 PATH="$1:$PATH" bash "$2" "$3" "$4" 2>&1)
  [[ "$out" == *"rc=1"* && "$out" != *"$4"* && -n "$(cat "$5")" && ! -e "$(cat "$5")" ]]' _ "$ST" "$TMP/pro_falha.sh" "$RAIZ/baseline.sh" "$TOK" "$STUB_PRO_FILE"
mkdir -p "$TMP/tdir"; : > "$TMP/tdir/attach.yaml"
t "trap: limpar_temp apaga a pasta do arquivo de token se o script morrer" no_baseline 'TMPS=("$1"); limpar_temp; [[ ! -e "$1" ]]' "$TMP/tdir"
t "token nunca vai para o .env, resumo ou echo (política no código)" bash -c '
  ! grep -nE "echo[^#]*PRO_TOKEN|PRO_TOKEN[^#]*>> *\"?\\\$LOG" baseline.sh &&
  ! sed -n "/^salvar_env()/,/^}/p" baseline.sh | grep -q PRO_TOKEN &&
  ! sed -n "/RESUMO — nada foi alterado/,/read -rp \"Aplicar/p" baseline.sh | grep -q "PRO_TOKEN" &&
  ! grep -nE "pro attach[^|\"]*(PRO_TOKEN|\\\$t\b)" baseline.sh'
t "token lido sem eco (read -rs) de /dev/tty"           bash -c 'grep -q "read -rsp \"  Token do Ubuntu Pro" baseline.sh && grep "read -rsp \"  Token do Ubuntu Pro" baseline.sh | grep -q "/dev/tty"'
t "validação do formato do token"                        no_baseline 'val_token_pro "C13abcDEF456ghi789" && ! val_token_pro "curto" && ! val_token_pro "tem espaco no meio" && ! val_token_pro "aspas\"123456" && ! val_token_pro "$(printf "a%.0s" {1..300})"'
t "já anexado → pro_anexado verdadeiro (e a pergunta é pulada)" env STUB_PRO_JSON='{"attached": true, "services": []}' PATH="$ST:$PATH" bash -c 'source "$1"; pro_anexado && grep -B1 -A3 "PRO_JA\" == sim" "$2" | grep -q "nada a fazer"' _ "$RAIZ/baseline.sh" "$RAIZ/baseline.sh"
t "não anexado → pro_anexado falso"                      env STUB_PRO_JSON='{"attached": false, "services": []}' PATH="$ST:$PATH" bash -c 'source "$1"; ! pro_anexado' _ "$RAIZ/baseline.sh"
t "padrão da pergunta é nao"                             grep -q 'PRO_ANEXAR "$(p PRO_ANEXAR nao)"\|"$(p PRO_ANEXAR nao)" val_simnao' baseline.sh
t "ubuntu-pro-client só é instalado se for anexar"       grep -q 'PRO_ANEXAR" == sim .*PKGS+=(ubuntu-pro-client)' baseline.sh
t "verify: estado anexado lista os serviços habilitados" env STUB_PRO_JSON='{"attached": true, "services": [{"name":"livepatch","status":"enabled"},{"name":"esm-infra","status":"enabled"},{"name":"ros","status":"disabled"}]}' PATH="$ST:$PATH" bash -c 'source "$1"; [[ $(pro_estado) == "sim livepatch esm-infra" ]]' _ "$RAIZ/baseline-verify.sh"
t "verify: não anexado"                                  env STUB_PRO_JSON='{"attached": false}' PATH="$ST:$PATH" bash -c 'source "$1"; [[ $(pro_estado) == nao ]]' _ "$RAIZ/baseline-verify.sh"
mkdir -p "$TMP/vazio"
t "verify: sem o comando pro → ausente"                  env PATH="$TMP/vazio" /bin/bash -c 'source "$1"; [[ $(pro_estado) == ausente ]]' _ "$RAIZ/baseline-verify.sh"
t "verify: AVISO só se o .env pediu (PRO_ANEXAR=sim) e não está anexado" bash -c 'grep -B1 -A2 "PRO_ANEXAR)\" == sim && \"\$PRO_E\" != sim" baseline-verify.sh | grep -q AVISO'
t "arquivo de respostas: PRO_ANEXAR=sim entra; token NÃO é chave do arquivo" no_baseline 'declare -A RESP=([PRO_ANEXAR]=sim [PRO_TOKEN]=naoleia); pergunta PRO_ANEXAR T "" "" "" val_simnao >/dev/null; [[ $PRO_ANEXAR == sim && -z ${PRO_TOKEN:-} ]]'

sec "Contrato do baseline.env (chaves que outros produtos leem)"
CONTRATO="BASELINE_VERSAO ADMIN_USER SSH_PORT GESTAO_SSH SSH_USUARIOS SNMP SNMP_ORIGENS SNMP_USER SNMP_LOCATION SNMP_CONTACT"
t "salvar_env grava todas as chaves do contrato"         no_baseline "ENV_FILE=\"$TMP/c.env\"; VERSAO=2.2.0; salvar_env; for k in $CONTRATO; do grep -q \"^\${k}=\" \"\$ENV_FILE\" || { echo \"falta \$k\"; exit 1; }; done"
t "README documenta cada chave do contrato"              bash -c 'sed -n "/Contrato do baseline.env/,\$p" README.md > "$2"; for k in $1; do grep -q "\`$k\`" "$2" || { echo "README sem $k"; exit 1; }; done' _ "$CONTRATO" "$TMP/contrato.md"
t "CHANGELOG.md existe e registra a 2.2.0"                bash -c 'grep -q "2.2.0" CHANGELOG.md && grep -qi "renomear\|renomeada\|renomeação" CHANGELOG.md'
t "nenhum rename silencioso: chaves do contrato continuam no código" bash -c 'for k in SSH_PORT GESTAO_SSH SSH_USUARIOS SNMP_ORIGENS SNMP_USER SNMP_LOCATION SNMP_CONTACT; do grep -q "\b$k\b" baseline.sh || exit 1; done'


sec "Conflito de SSH com arquivo de OUTRO produto (o sshd usa a 1.ª ocorrência) — sshd real"
if command -v sshd >/dev/null 2>&1 || [[ -x /usr/sbin/sshd ]]; then
export PATH="$PATH:/usr/sbin:/sbin"
ssh-keygen -q -t ed25519 -N '' -f "$TMP/hk"
novo_ssh() { # novo_ssh NOME -> cria $TMP/ssh/NOME com sshd_config (HostKey próprio + Include) e conf.d/
  local d="$TMP/ssh/$1"; mkdir -p "$d/conf.d"
  printf 'HostKey %s\nInclude %s/conf.d/*.conf\nUsePAM no\n' "$TMP/hk" "$d" > "$d/sshd_config"; echo "$d"
}
cat > "$TMP/cfl.sh" <<'EOT'
source "$RAIZ/baseline.sh"
D=$1
SSHD_PRINCIPAL=$D/sshd_config; SSHD_ARQ=$D/conf.d/10-baseline.conf; SSHD_ANTIGO=$D/conf.d/10-g2-hardening.conf
ADMIN_USER=daemon; SSH_PORT=44320; SSH_USUARIOS=${SU:-daemon}; SSH_TCP_FWD=${TCP:-nao}; SSH_AGENT_FWD=nao; SSH_GRACE=30; SSH_ALIVE_INT=300; SSH_ALIVE_MAX=2; TS=t
ssh_conflitos
for x in "${SSH_CONF_PARAR[@]}"; do echo "PARAR|$x"; done
for x in "${SSH_CONF_AVISO[@]}"; do echo "AVISO|$x"; done
for k in "${!SSH_OVERRIDE[@]}"; do echo "OVR|$k=${SSH_OVERRIDE[$k]}"; done
EOT
cfl() { RAIZ="$RAIZ" bash "$TMP/cfl.sh" "$1"; }

D=$(novo_ssh incidente); printf 'ClientAliveInterval 3\nClientAliveCountMax 15\n' > "$D/conf.d/01-dns-admin.conf"
cfl "$D" > "$TMP/o.incidente"
t "o incidente (01-dns-admin.conf: ClientAliveInterval 3 / CountMax 15) NÃO para: só avisa, com a frase exata" bash -c '
  ! grep -q "^PARAR|" "$1" &&
  grep -qxF "AVISO|SSH ClientAliveInterval: escolhido 300, mas 01-dns-admin.conf define 3 e VENCE (o sshd usa a 1.ª ocorrência)" "$1" &&
  grep -qxF "AVISO|SSH ClientAliveCountMax: escolhido 2, mas 01-dns-admin.conf define 15 e VENCE (o sshd usa a 1.ª ocorrência)" "$1"' _ "$TMP/o.incidente"
t "...e o valor que vence vira o ESPERADO (SSH_OVERRIDE)" bash -c 'grep -qx "OVR|clientaliveinterval=3" "$1" && grep -qx "OVR|clientalivecountmax=15" "$1"' _ "$TMP/o.incidente"
# o sshd real, com o 10-baseline.conf JÁ aplicado: o autoteste (sshd_diverge) compara com o esperado real
cat > "$TMP/dv.sh" <<'EOT'
source "$RAIZ/baseline.sh"
D=$1
SSHD_PRINCIPAL=$D/sshd_config; SSHD_ARQ=$D/conf.d/10-baseline.conf; SSHD_ANTIGO=$D/conf.d/10-g2-hardening.conf
ADMIN_USER=daemon; SSH_PORT=44320; SSH_USUARIOS=daemon; SSH_TCP_FWD=nao; SSH_AGENT_FWD=nao; SSH_GRACE=30; SSH_ALIVE_INT=300; SSH_ALIVE_MAX=2; TS=t
ssh_conflitos
gerar_sshd_conf > "$SSHD_ARQ"                                   # "aplica"
[[ ${USAR_OVR:-1} == 1 ]] || SSH_OVERRIDE=()
[[ -z "${SURPRESA:-}" ]] || printf '%s\n' "$SURPRESA" > "$D/conf.d/00-surpresa.conf"   # algo muda DEPOIS da simulação (diferença inesperada)
sshd -T -f "$D/sshd_config" -C user=daemon,host=localhost,addr=127.0.0.1 | sshd_diverge
EOT
t "autoteste: efetivo (com o 01-outro vencendo) bate com o esperado REAL → passa" env RAIZ="$RAIZ" bash "$TMP/dv.sh" "$D"
D2=$(novo_ssh incidente2); printf 'ClientAliveInterval 3\nClientAliveCountMax 15\n' > "$D2/conf.d/01-dns-admin.conf"
t "(controle) com a expectativa antiga o MESMO cenário divergia — era o bug do teste real" bash -c '! RAIZ="$1" USAR_OVR=0 bash "$2" "$3"' _ "$RAIZ" "$TMP/dv.sh" "$D2"
D3=$(novo_ssh inesperado); printf 'ClientAliveInterval 3\n' > "$D3/conf.d/01-dns-admin.conf"
t "diferença INESPERADA (outro arquivo muda DEPOIS da simulação) continua reprovando → abortaria e voltaria" bash -c '! RAIZ="$1" SURPRESA="LoginGraceTime 99" bash "$2" "$3"' _ "$RAIZ" "$TMP/dv.sh" "$D3"

for CASO in "PasswordAuthentication yes|PasswordAuthentication" "PermitRootLogin yes|PermitRootLogin" "PermitRootLogin prohibit-password|PermitRootLogin" \
            "PubkeyAuthentication no|PubkeyAuthentication" "KbdInteractiveAuthentication yes|KbdInteractiveAuthentication" "X11Forwarding yes|X11Forwarding" \
            "AllowTcpForwarding yes|AllowTcpForwarding" "AllowAgentForwarding yes|AllowAgentForwarding" "MaxAuthTries 6|MaxAuthTries"; do
  LINHA=${CASO%%|*}; NOME=${CASO##*|}; D=$(novo_ssh "seg-${LINHA// /_}"); printf '%s\n' "$LINHA" > "$D/conf.d/01-outro.conf"
  t "segurança menos segura PARA e cita o arquivo: 01-outro.conf → $LINHA" bash -c '
    out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^PARAR|SSH $4: .*01-outro.conf define .* e VENCE .*MENOS seguro" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D" "$NOME"
done
D=$(novo_ssh porta22); printf 'Port 22\n' > "$D/conf.d/01-outro.conf"
t "Port: outro arquivo escutando também na 22 → PARA e cita o arquivo" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^PARAR|SSH Port: .*01-outro.conf" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh porta-igual); printf 'Port 44320\n' > "$D/conf.d/01-outro.conf"
cfl "$D" > "$TMP/o.porta-igual"
t "Port 44320 repetida em outro arquivo + baseline 44320: segue SEM aviso (o sshd escuta uma vez)" bash -c '[[ ! -s "$1" ]]' _ "$TMP/o.porta-igual"
t "...com o 10-baseline.conf aplicado, o sshd real lista a porta DUAS vezes e o sshd_diverge passa mesmo assim" bash -c '
  RAIZ="$1" bash "$2" "$3" && [[ $(sshd -T -f "$3/sshd_config" -C user=daemon,host=localhost,addr=127.0.0.1 | grep -c "^port 44320$") == 2 ]]' _ "$RAIZ" "$TMP/dv.sh" "$D"
D=$(novo_ssh porta-2222); printf 'Port 2222\n' > "$D/conf.d/01-outro.conf"
t "01-outro.conf 'Port 2222': PARA (porta a mais) citando o arquivo" bash -c '
  out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^PARAR|SSH Port: escolhido 44320, mas o sshd escutaria em: 2222 44320 (porta a mais: 2222; 01-outro.conf define Port; Port ACUMULA" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh porta-mista); printf 'Port 44320\nPort 2222\nPort 44320\n' > "$D/conf.d/01-outro.conf"
t "Port 44320 + 2222 + 44320: só a 2222 é 'a mais'" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "porta a mais: 2222;" <<<"$out" && ! grep -q "porta a mais: 2222 44320\|porta a mais: 44320" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
t "ssh_portas_dif: conjunto sem repetição" no_baseline '
  ssh_portas_dif 44320 "44320" && ssh_portas_dif 44320 "44320 44320 44320" && ssh_portas_dif 44320 "" >/dev/null; [[ $? -ne 0 ]]
  [[ $(ssh_portas_dif 44320 "2222 44320 2222") == "porta a mais: 2222" ]]
  [[ $(ssh_portas_dif 44320 "2222") == "porta a mais: 2222; falta a escolhida: 44320" ]]
  [[ $(ssh_portas_dif 44320 "") == "falta a escolhida: 44320" ]]'
D=$(novo_ssh allowusers); printf 'AllowUsers intruso\n' > "$D/conf.d/01-outro.conf"
t "AllowUsers: outro arquivo SOMA usuário → PARA e cita arquivo e usuário" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^PARAR|SSH AllowUsers: .*01-outro.conf acrescenta intruso" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh restritivo); printf 'MaxAuthTries 2\nPasswordAuthentication no\n' > "$D/conf.d/01-outro.conf"
t "segurança MAIS restritiva (MaxAuthTries 2) só avisa e segue" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); ! grep -q "^PARAR|" <<<"$out" && grep -q "^AVISO|SSH MaxAuthTries: escolhido 3, mas 01-outro.conf define 2 e VENCE.*mais restritivo" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh depois); printf 'ClientAliveInterval 3\nPasswordAuthentication yes\n' > "$D/conf.d/99-depois.conf"
t "arquivo que ordena DEPOIS do 10-baseline.conf não vence: nada a avisar" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); [[ -z "$out" ]]' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh anterior); printf 'ClientAliveInterval 77\nPasswordAuthentication yes\n' > "$D/conf.d/10-baseline.conf"
t "10-baseline.conf de uma execução ANTERIOR é substituído pelo candidato (não conta como conflito)" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); [[ -z "$out" ]]' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh principal); printf 'HostKey %s\nClientAliveInterval 7\nInclude %s/conf.d/*.conf\nUsePAM no\n' "$TMP/hk" "$D" > "$D/sshd_config"
t "linha no sshd_config ANTES do Include também vence (e é atribuída a sshd_config)" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^AVISO|SSH ClientAliveInterval: escolhido 300, mas sshd_config define 7 e VENCE" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh depoisdoinclude); printf 'HostKey %s\nInclude %s/conf.d/*.conf\nClientAliveInterval 7\nUsePAM no\n' "$TMP/hk" "$D" > "$D/sshd_config"
t "linha no sshd_config DEPOIS do Include perde para o 10-baseline.conf" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); [[ -z "$out" ]]' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh semincl); printf 'HostKey %s\nUsePAM no\n' "$TMP/hk" > "$D/sshd_config"
t "sshd_config sem Include de sshd_config.d: PARA (o 10-baseline.conf seria ignorado)" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^PARAR|.*não inclui .*10-baseline.conf" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh relativo); printf 'HostKey %s\nInclude conf.d/*.conf\nUsePAM no\n' "$TMP/hk" > "$D/sshd_config"; printf 'LoginGraceTime 99\n' > "$D/conf.d/01-outro.conf"
t "Include com caminho relativo (conf.d/*.conf) também é seguido" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^AVISO|SSH LoginGraceTime: escolhido 30, mas 01-outro.conf define 99 e VENCE" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh match); printf 'Match User daemon\n  PasswordAuthentication yes\n' > "$D/conf.d/01-outro.conf"
t "bloco Match de outro arquivo que reabre senha para o admin: PARA e cita o Match" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^PARAR|SSH PasswordAuthentication: .*01-outro.conf (dentro de um bloco Match) define yes" <<<"$out"' _ "$RAIZ" "$TMP/cfl.sh" "$D"
D=$(novo_ssh intocado); printf 'ClientAliveInterval 3\nPasswordAuthentication yes\n' > "$D/conf.d/01-outro.conf"; printf 'Port 2222\n' > "$D/conf.d/50-cloud-init.conf"
( cd "$D" && find . -type f | sort | xargs sha256sum; ls -la --time-style=+%s conf.d ) > "$TMP/antes.sum"
cfl "$D" >/dev/null
( cd "$D" && find . -type f | sort | xargs sha256sum; ls -la --time-style=+%s conf.d ) > "$TMP/depois.sum"
t "NUNCA edita nem move arquivo de outro produto (conteúdo, lista e datas idênticos)" cmp -s "$TMP/antes.sum" "$TMP/depois.sum"
t "política: nenhum mv/rm/sed -i/escrita em arquivos de sshd_config.d além do próprio (10-baseline.conf) e do da v1" bash -c '
  ! sed -n "/^ssh_conflitos()/,/^}/p;/^py_ssh()/,/^}/p" baseline.sh | grep -nE "(^|[^a-z_])(mv|rm|sed -i|chmod|chown|install|tee)( |$)|>> *\"?\$SSHD" '
t "política: o único mv em sshd_config.d é o do arquivo da própria v1 (10-g2-hardening.conf)" bash -c '[[ $(grep -cE "(^|[ ;&])mv .*(sshd_config|SSHD_)" baseline.sh) == 1 ]] && grep -q "mv \"\$SSHD_ANTIGO\" \"\$BK/\"" baseline.sh'

t "ssh_menos_seguro: tabela"  no_baseline '
  ssh_menos_seguro passwordauthentication no yes && ! ssh_menos_seguro passwordauthentication no no && ! ssh_menos_seguro passwordauthentication yes no &&
  ssh_menos_seguro permitrootlogin no prohibit-password && ssh_menos_seguro permitrootlogin no yes &&
  ssh_menos_seguro pubkeyauthentication yes no && ssh_menos_seguro maxauthtries 3 6 && ! ssh_menos_seguro maxauthtries 3 2 &&
  ssh_menos_seguro allowtcpforwarding no local && ! ssh_menos_seguro allowtcpforwarding yes no && ssh_menos_seguro port 1 2 &&
  ! ssh_menos_seguro clientaliveinterval 300 3 && [[ $(ssh_classe clientaliveinterval 300 3) == conforto && $(ssh_classe logingracetime 30 120) == conforto ]] &&
  [[ $(ssh_classe passwordauthentication no yes) == parar && $(ssh_classe maxauthtries 3 2) == restritivo ]]'

# verify: mesma regra, com o sshd real e o 10-baseline.conf já aplicado
cat > "$TMP/vf.sh" <<'EOT'
source "$RAIZ/baseline-verify.sh"
D=$1
SSHD_PRINCIPAL=$D/sshd_config; SSHD_ARQ=$D/conf.d/10-baseline.conf; SSHD_ANTIGO=$D/conf.d/10-g2-hardening.conf
declare -A E=([SSH_TCP_FWD]=nao [SSH_AGENT_FWD]=nao [SSH_GRACE]=30 [SSH_ALIVE_INT]=300 [SSH_ALIVE_MAX]=2 [SSH_USUARIOS]=daemon)
( source "$RAIZ/baseline.sh" >/dev/null 2>&1; ADMIN_USER=daemon; SSH_PORT=44320; SSH_USUARIOS=daemon; SSH_TCP_FWD=nao; SSH_AGENT_FWD=nao; SSH_GRACE=30; SSH_ALIVE_INT=300; SSH_ALIVE_MAX=2; gerar_sshd_conf ) > "$SSHD_ARQ"
OUT=$(sshd -T -f "$D/sshd_config" -C user=daemon,host=localhost,addr=127.0.0.1)
PASS=0; FAIL=0; AVISO=0
ssh_confere_portas 44320 "$OUT"; for par in "permitrootlogin no" "passwordauthentication no" "kbdinteractiveauthentication no" "pubkeyauthentication yes"; do ssh_confere_valor "${par% *}" "${par#* }" "$OUT"; done
confere_ssh_efetivo "$OUT"
echo "RES $PASS $FAIL $AVISO"
EOT
vf() { RAIZ="$RAIZ" bash "$TMP/vf.sh" "$1"; }
D=$(novo_ssh vf-limpo)
t "verify: sem conflito → tudo OK (11 OK, 0 FALHA, 0 AVISO)"       bash -c 'vf=$(RAIZ="$1" bash "$2" "$3"); grep -q "^RES 11 0 0$" <<<"$vf"' _ "$RAIZ" "$TMP/vf.sh" "$D"
D=$(novo_ssh vf-conforto); printf 'ClientAliveInterval 3\nClientAliveCountMax 15\n' > "$D/conf.d/01-dns-admin.conf"
t "verify: conforto vencido por outro arquivo → AVISO 'outro arquivo vence', NÃO falha" bash -c '
  vf=$(RAIZ="$1" bash "$2" "$3" 2>&1); grep -q "^RES 9 0 2$" <<<"$vf" && grep -q "outro arquivo vence: 01-dns-admin.conf define 3 (o baseline escolheu 300)" <<<"$vf"' _ "$RAIZ" "$TMP/vf.sh" "$D"
D=$(novo_ssh vf-seguranca); printf 'PasswordAuthentication yes\n' > "$D/conf.d/01-outro.conf"
t "verify: segurança menos segura de outro arquivo → FALHA citando o arquivo" bash -c '
  vf=$(RAIZ="$1" bash "$2" "$3" 2>&1); grep -q "^RES .* 1 0$" <<<"$vf" && grep -q "passwordauthentication esperado no, efetivo yes — 01-outro.conf VENCE com valor MENOS seguro" <<<"$vf"' _ "$RAIZ" "$TMP/vf.sh" "$D"
D=$(novo_ssh vf-allowusers); printf 'AllowUsers intruso\n' > "$D/conf.d/01-outro.conf"
t "verify: AllowUsers somado por outro arquivo → FALHA citando o arquivo" bash -c 'vf=$(RAIZ="$1" bash "$2" "$3" 2>&1); grep -q "allowusers esperado daemon, efetivo daemon intruso (01-outro.conf" <<<"$vf"' _ "$RAIZ" "$TMP/vf.sh" "$D"
D=$(novo_ssh vf-adulterado)
cat > "$TMP/vf_adulterado.sh" <<'EOT'
source "$RAIZ/baseline-verify.sh"
D=$1
SSHD_PRINCIPAL=$D/sshd_config; SSHD_ARQ=$D/conf.d/10-baseline.conf; SSHD_ANTIGO=$D/conf.d/10-g2-hardening.conf
printf 'LoginGraceTime 11\n' > "$SSHD_ARQ"                    # alguém editou o arquivo do baseline: nenhum OUTRO arquivo o define
PASS=0; FAIL=0; AVISO=0
ssh_confere_valor logingracetime 30 "$(sshd -T -f "$D/sshd_config" -C user=daemon,host=localhost,addr=127.0.0.1)" 2>&1
echo "RES $PASS $FAIL $AVISO"
EOT
t "verify: diferença SEM dono conhecido (10-baseline.conf editado) → FALHA" bash -c 'out=$(RAIZ="$1" bash "$2" "$3"); grep -q "^RES 0 1 0$" <<<"$out" && grep -q "10-baseline.conf foi editado" <<<"$out"' _ "$RAIZ" "$TMP/vf_adulterado.sh" "$D"
D=$(novo_ssh vf-porta-igual); printf 'Port 44320\n' > "$D/conf.d/01-outro.conf"
t "verify: Port repetida com o mesmo valor → OK (11 OK, 0 FALHA, 0 AVISO)" bash -c 'vf=$(RAIZ="$1" bash "$2" "$3"); grep -q "^RES 11 0 0$" <<<"$vf"' _ "$RAIZ" "$TMP/vf.sh" "$D"
D=$(novo_ssh vf-porta-2222); printf 'Port 2222\n' > "$D/conf.d/01-outro.conf"
t "verify: Port 2222 de outro arquivo → FALHA 'porta a mais' citando o arquivo" bash -c 'vf=$(RAIZ="$1" bash "$2" "$3" 2>&1); grep -q "port esperado 44320, efetivo 2222 44320 (porta a mais: 2222; 01-outro.conf define Port" <<<"$vf"' _ "$RAIZ" "$TMP/vf.sh" "$D"
t "verify: o bloco py_ssh/ssh_* é CÓPIA EXATA do baseline.sh" bash -c '
  a=$(source ./baseline.sh; declare -f py_ssh ssh_nome ssh_menos_seguro ssh_classe ssh_quem ssh_quem_todos)
  b=$(source ./baseline-verify.sh; declare -f py_ssh ssh_nome ssh_menos_seguro ssh_classe ssh_quem ssh_quem_todos)
  [[ -n $a && "$a" == "$b" ]]'
t "verify: não usa mais 'grep -qx' puro para port/permitrootlogin/… (agora explica quem vence)" bash -c '! grep -nE "chk \"sshd efetivo: \\\$par\"" baseline-verify.sh'

sec "Conflito de SSH — fluxo do baseline.sh"
t "ssh_conflitos roda DEPOIS das perguntas de SSH e ANTES do resumo/aplicação" bash -c '
  a=$(grep -n "^pergunta SSH_ALIVE_MAX" baseline.sh | cut -d: -f1); b=$(grep -n "^ssh_conflitos$" baseline.sh | cut -d: -f1)
  c=$(grep -n "RESUMO — nada foi alterado" baseline.sh | cut -d: -f1); d=$(grep -n "^gerar_sshd_conf > \"\$SSHD_ARQ\"" baseline.sh | cut -d: -f1)
  [[ -n $a && -n $b && -n $c && -n $d && $a -lt $b && $b -lt $c && $c -lt $d ]]'
t "conflito de segurança chama pare ANTES de qualquer alteração"  bash -c 'grep -A8 "^ssh_conflitos$" baseline.sh | grep -q "SSH_CONF_PARAR\[@\]" && grep -A8 "^ssh_conflitos$" baseline.sh | grep -q "pare \"Nada foi alterado"'
t "o resumo lista os avisos de conflito de conforto"              bash -c 'sed -n "/RESUMO — nada foi alterado/,/read -rp \"Aplicar/p" baseline.sh | grep -q "SSH_CONF_AVISO\[@\]"'
else
  if [[ ${BASELINE_EXIGE_SSHD:-0} == 1 ]]; then N=$((N+1)); FALHAS=$((FALHAS+1)); echo "  FALHA sshd ausente: testes de conflito de SSH não rodaram"; else echo "  skip  sshd não instalado"; fi
fi


sec "2) Abortado: a versão nova do verify; o verify imprime a PRÓPRIA versão"
t "pare: aponta para o baseline-verify.sh ao lado do script"  bash -c 'out=$(source ./baseline.sh; LOG=/x; pare "teste" 2>&1); rc=$?; [[ $rc -ne 0 && "$out" == *"Abortado."* && "$out" == *"Para conferir com a versão nova: sudo bash '"$RAIZ"'/baseline-verify.sh"* ]]'
mkdir -p "$TMP/sozinho"; cp baseline.sh "$TMP/sozinho/"
t "pare: sem baseline-verify.sh ao lado, manda baixar o da mesma versão" bash -c 'out=$(source "$1"; LOG=/x; pare "teste" 2>&1); [[ "$out" == *"baixe o baseline-verify.sh da v2.2.0"* && "$out" == *"o '"'"'sudo baseline-verify'"'"' instalado pode ser o da versão anterior"* ]]' _ "$TMP/sozinho/baseline.sh"
t "toda mensagem 'Abortado' sai pelo pare (um único lugar)"      bash -c '[[ $(grep -c "Abortado" baseline.sh) == 1 ]] && grep -n "Abortado" baseline.sh | grep -q "echo \"Abortado. Log"'
t "conflito de SSH e autoteste abortam via pare"                  bash -c 'grep -q "pare \"Nada foi alterado (conflito de SSH" baseline.sh && grep -q "pare \"Autoteste do SSH falhou" baseline.sh'
t "verify imprime a SUA versão e a de quem aplicou o padrão"      bash -c 'source ./baseline-verify.sh; declare -A E=([BASELINE_VERSAO]=2.1.0); out=$(verify_cabecalho); [[ "$out" == *"baseline-verify v$VERIFY_VERSAO "* && "$out" == *"padrão aplicado pela v2.1.0"* ]]'
t "VERIFY_VERSAO == VERSAO do baseline.sh"                        bash -c '[[ $(sed -n "s/^VERIFY_VERSAO=\"\([^\"]*\)\".*/\1/p" baseline-verify.sh) == $(sed -n "s/^VERSAO=\"\([^\"]*\)\".*/\1/p" baseline.sh) ]]'
t "verify: ssh_portas_dif/snmpd_de_outro são CÓPIAS EXATAS do baseline.sh" bash -c '
  a=$(source ./baseline.sh; declare -f ssh_portas_dif snmpd_de_outro)
  b=$(source ./baseline-verify.sh; declare -f ssh_portas_dif snmpd_de_outro)
  [[ -n $a && "$a" == "$b" ]]'

sec "3) SNMP com snmpd.conf de OUTRO produto"
SS_EXATO=$'UNCONN 0 0 179.125.120.36:161 0.0.0.0:*\nUNCONN 0 0 127.0.0.1:161 0.0.0.0:*'
SS_TODOS=$'UNCONN 0 0 0.0.0.0:161 0.0.0.0:*\nUNCONN 0 0 [::]:161 [::]:*'
SS_V6=$'UNCONN 0 0 [::]:161 [::]:*'
SS_NADA=$'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*'
SS_PARECIDO=$'UNCONN 0 0 1179.125.120.36:161 0.0.0.0:*'
t "snmp_cobre: endereço exato"                       no_verify '[[ $(snmp_cobre "$1" 179.125.120.36) == exato && $(snmp_cobre "$1" 127.0.0.1) == exato ]]' "$SS_EXATO"
t "snmp_cobre: 0.0.0.0:161 / [::]:161 cobrem os endereços ('todos')" no_verify '[[ $(snmp_cobre "$1" 179.125.120.36) == todos && $(snmp_cobre "$1" 127.0.0.1) == todos ]]' "$SS_TODOS"
t "snmp_cobre: SÓ 0.0.0.0:161 cobre (sem [::])"        no_verify '[[ $(snmp_cobre "$1" 179.125.120.36) == todos && $(snmp_cobre "$1" 127.0.0.1) == todos ]]' $'UNCONN 0 0 0.0.0.0:161 0.0.0.0:*'
t "snmp_cobre: SÓ *:161 cobre"                           no_verify '[[ $(snmp_cobre "$1" 127.0.0.1) == todos ]]' $'UNCONN 0 0 *:161 *:*'
t "snmp_cobre: outra porta em 0.0.0.0 (0.0.0.0:1610) NÃO cobre" no_verify '[[ -z $(snmp_cobre "$1" 127.0.0.1) ]]' $'UNCONN 0 0 0.0.0.0:1610 0.0.0.0:*'
t "snmp_cobre: só [::]:161 também cobre (dual-stack)"  no_verify '[[ $(snmp_cobre "$1" 127.0.0.1) == todos ]]' "$SS_V6"
t "snmp_cobre: sem 161 → nada"                         no_verify '[[ -z $(snmp_cobre "$1" 127.0.0.1) ]]' "$SS_NADA"
t "snmp_cobre: 1179.125.120.36 NÃO casa com 179.125.120.36" no_verify '[[ -z $(snmp_cobre "$1" 179.125.120.36) ]]' "$SS_PARECIDO"

printf '# Gerado por baseline v2.2.0 em x — somente SNMPv3\nagentaddress udp:179.125.120.36:161,udp:127.0.0.1:161\nsysLocation "Sala"\nrouser monitorv3 priv\n' > "$TMP/snmpd.baseline"
printf 'agentAddress udp:161,udp6:161\nsysLocation Datacenter_Central\nsysContact suporte@exemplo.com.br\nrouser monitorv3 priv\n' > "$TMP/snmpd.outro"
printf 'agentAddress udp:161,udp6:161\nsysLocation X\n' > "$TMP/snmpd.outro_sem_rouser"
printf 'agentAddress udp:161\nrocommunity public\nrouser monitorv3 priv\n' > "$TMP/snmpd.outro_community"
printf '' > "$TMP/snmpd.vazio"
cat > "$ST/dpkg-query" <<'EOT'
#!/usr/bin/env bash
[[ -n "${STUB_MD5:-}" ]] && printf ' %s %s\n' "$STUB_SNMPD" "$STUB_MD5"
exit 0
EOT
chmod +x "$ST/dpkg-query"
t "snmpd_de_outro: arquivo do baseline (marca '# Gerado por baseline v') → não é de outro"  no_baseline 'SNMPD_ARQ=$1; ! snmpd_de_outro' "$TMP/snmpd.baseline"
t "snmpd_de_outro: arquivo de outro produto → é de outro"                                    no_baseline 'SNMPD_ARQ=$1; snmpd_de_outro' "$TMP/snmpd.outro"
t "snmpd_de_outro: vazio ou inexistente → não é de outro"                                   no_baseline 'SNMPD_ARQ=$1; ! snmpd_de_outro && SNMPD_ARQ=/nao/existe && ! snmpd_de_outro' "$TMP/snmpd.vazio"
M5=$(md5sum "$TMP/snmpd.outro" | cut -d' ' -f1)
t "snmpd_de_outro: arquivo de fábrica do pacote (md5 do dpkg) → NÃO conta como de outro produto" env STUB_MD5="$M5" STUB_SNMPD="$TMP/snmpd.outro" PATH="$ST:$PATH" bash -c 'source "$1"; SNMPD_ARQ=$2; ! snmpd_de_outro' _ "$RAIZ/baseline.sh" "$TMP/snmpd.outro"
t "snmpd_de_outro: conffile do pacote MODIFICADO (md5 diferente) → é de outro" env STUB_MD5="00000000000000000000000000000000" STUB_SNMPD="$TMP/snmpd.outro" PATH="$ST:$PATH" bash -c 'source "$1"; SNMPD_ARQ=$2; snmpd_de_outro' _ "$RAIZ/baseline.sh" "$TMP/snmpd.outro"

cp "$TMP/snmpd.outro" "$TMP/snmpd.intocado"
t "baseline.sh NÃO sobrescreve o snmpd.conf de outro produto (conteúdo idêntico, retorno 1)" no_baseline 'SNMPD_ARQ=$1; SNMPD_OUTRO=sim; V4=1.2.3.4; SNMP_LOCATION=X; SNMP_CONTACT=y; SNMP_USER=u; ! snmpd_gravar_conf && cmp -s "$1" "$2"' "$TMP/snmpd.intocado" "$TMP/snmpd.outro"
t "...e grava o do baseline (com a marca) quando não é de outro"   no_baseline 'SNMPD_ARQ=$1; SNMPD_OUTRO=nao; V4=1.2.3.4; SNMP_LOCATION=Sala; SNMP_CONTACT=y; SNMP_USER=monitorv3; snmpd_gravar_conf && head -1 "$1" | grep -q "^# Gerado por baseline v2.2.0" && grep -qx "rouser monitorv3 priv" "$1"' "$TMP/snmpd.novo"
t "resumo: 'snmpd.conf de outro produto — mantido; só o usuário SNMPv3 é conferido'" bash -c 'sed -n "/RESUMO — nada foi alterado/,/read -rp \"Aplicar/p" baseline.sh | grep -q "snmpd.conf de outro produto — mantido; só o usuário SNMPv3 é conferido"'
t "com snmpd.conf de outro produto o baseline NÃO pede as senhas"  bash -c '
  a=$(grep -n "if \[\[ \"\$SNMPD_OUTRO\" == sim \]\]; then" baseline.sh | head -1 | cut -d: -f1)
  b=$(awk -v a="$a" "NR>a && /^  else\$/{print NR; exit}" baseline.sh)
  [[ -n $a && -n $b ]] && ! sed -n "${a},${b}p" baseline.sh | grep -q "ler_senha"'
t "a decisão 'de outro produto' vem ANTES de instalar pacotes (o apt cria um snmpd.conf de fábrica)" bash -c 'a=$(grep -n "snmpd_de_outro && SNMPD_OUTRO=sim" baseline.sh | cut -d: -f1); b=$(grep -n "install \"\${PKGS\[@\]}\"" baseline.sh | cut -d: -f1); [[ -n $a && -n $b && $a -lt $b ]]'
t "etapa 4/4: sem sobrescrever (snmpd_gravar_conf) quando de outro produto" bash -c 'sed -n "/^info \"4\/4 SNMPv3\"/,/^# REGISTRO/p" baseline.sh | grep -q "if ! snmpd_gravar_conf" && ! grep -n "cat > /etc/snmp/snmpd.conf" baseline.sh'

cfg() { # cfg CONF "SS" -> roda confere_snmp_conf e imprime RES PASS FAIL AVISO
  SNMPD_ARQ_T=$1 SS_T=$2 EXTRA_T=${3:-} no_verify 'SNMPD_ARQ=$SNMPD_ARQ_T; declare -A E=([SNMP_LOCATION]=Datacenter_Central [SNMP_CONTACT]=suporte@exemplo.com.br); PASS=0; FAIL=0; AVISO=0
    confere_snmp_conf "$SS_T" 179.125.120.36 monitorv3 2>&1; echo "RES $PASS $FAIL $AVISO"'
}
cfg "$TMP/snmpd.baseline" "$SS_EXATO" > "$TMP/c1.out"
t "verify: snmpd.conf do baseline com endereços exatos → 4 OK, 0 FALHA"  grep -q '^RES 4 0 0$' "$TMP/c1.out"
cfg "$TMP/snmpd.baseline" "$SS_NADA" > "$TMP/c2.out"
t "verify: snmpd.conf do baseline que NÃO escuta no IP → FALHA (como antes)" bash -c 'grep -q "^RES 2 2 0$" "$1" && grep -q "FALHA.* snmpd escutando em 179.125.120.36:161" "$1"' _ "$TMP/c2.out"
cfg "$TMP/snmpd.baseline" "$SS_TODOS" > "$TMP/c3.out"
t "verify: escuta em todos (0.0.0.0/[::]:161) = OK, dizendo 'inclui X'"  bash -c 'grep -q "^RES 4 0 0$" "$1" && grep -q "snmpd escuta em todos os endereços (0.0.0.0/\[::\]:161) — inclui 179.125.120.36:161" "$1" && grep -q "inclui 127.0.0.1:161" "$1"' _ "$TMP/c3.out"
cfg "$TMP/snmpd.outro" "$SS_TODOS" > "$TMP/c4.out"
t "verify: snmpd.conf de OUTRO produto escutando em todos → sem FALHA e diz 'é de outro produto'" bash -c 'grep -q "snmpd.conf é de outro produto" "$1" && grep -q "^RES .* 0 [0-9]*$" "$1" && grep -q "^RES 6 0 0$" "$1"' _ "$TMP/c4.out"
cfg "$TMP/snmpd.outro" "$SS_NADA" > "$TMP/c5.out"
t "verify: snmpd.conf de OUTRO produto que não escuta nos endereços → só AVISO informativo (nunca FALHA)" bash -c 'grep -q "^RES 4 0 2$" "$1" && grep -q "AVISO.*snmpd não escuta em 179.125.120.36:161 (snmpd.conf de outro produto: informativo)" "$1"' _ "$TMP/c5.out"
cfg "$TMP/snmpd.outro_sem_rouser" "$SS_TODOS" > "$TMP/c6.out"
t "verify: de outro produto SEM 'rouser <usuário> priv' continua FALHA"      bash -c 'grep -q "FALHA.* rouser monitorv3 priv" "$1"' _ "$TMP/c6.out"
cfg "$TMP/snmpd.outro_community" "$SS_TODOS" > "$TMP/c7.out"
t "verify: de outro produto COM community (v1/v2c) continua FALHA"           bash -c 'grep -q "FALHA.* Sem community" "$1"' _ "$TMP/c7.out"
printf 'agentAddress udp:161,udp6:161\nsysLocation Outro_Lugar\nsysContact outro@x\nrouser monitorv3 priv\n' > "$TMP/snmpd.diverge"
cfg "$TMP/snmpd.diverge" "$SS_TODOS" > "$TMP/c8.out"
t "verify: localização/contato de outro produto que não batem → 2 AVISOS, nunca FALHA" bash -c 'grep -q "^RES 4 0 2$" "$1" && grep -q "AVISO.*sysLocation Datacenter_Central no snmpd.conf (informativo)" "$1" && grep -q "AVISO.*sysContact suporte@exemplo.com.br no snmpd.conf (informativo)" "$1"' _ "$TMP/c8.out"

sec "4) Teste real do SNMP no verify: prompts, motivo da falha, local e IP, senhas fora do argv"
SEC_A='AuthSecret!1x'; SEC_P='PrivSecret!2y'
cat > "$ST/snmpget" <<'EOT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_SNMP_ARGS"
alvo=${@: -2:1}; var="STUB_MODE_${alvo//./_}"; modo=${!var:-ok}
cp "$SNMPCONFPATH/snmp.conf" "$STUB_SNMP_CONF" 2>/dev/null
stat -c %a "$SNMPCONFPATH/snmp.conf" > "$STUB_SNMP_MODE"; stat -c %a "$SNMPCONFPATH" > "$STUB_SNMP_DMODE"; echo "$SNMPCONFPATH" > "$STUB_SNMP_DIR"
case $modo in
  ok) echo "DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (123) 0:00:01.23"; exit 0;;
  timeout) echo "Timeout: No Response from $alvo." >&2; exit 1;;
  auth) echo "snmpget: Authentication failure (incorrect password, community or key)" >&2; exit 1;;
  digest) echo "snmpget: wrong digest" >&2; exit 1;;
  decrypt) echo "snmpget: Decryption error" >&2; exit 1;;
  user) echo "snmpget: Unknown user name" >&2; exit 1;;
  vaza) echo "snmpget: erro estranho com $(sed -n 's/^defAuthPassphrase //p' "$SNMPCONFPATH/snmp.conf") e $(sed -n 's/^defPrivPassphrase //p' "$SNMPCONFPATH/snmp.conf")" >&2; exit 1;;
esac
EOT
chmod +x "$ST/snmpget"
export STUB_SNMP_ARGS="$TMP/sn.args" STUB_SNMP_CONF="$TMP/sn.conf" STUB_SNMP_MODE="$TMP/sn.mode" STUB_SNMP_DMODE="$TMP/sn.dmode" STUB_SNMP_DIR="$TMP/sn.dir"
sg() { # sg MODO_LOCAL MODO_IP  -> executa snmp_confere_real e imprime tudo + RES
  STUB_MODE_127_0_0_1=$1 STUB_MODE_179_125_120_36=$2 PATH="$ST:$PATH" bash -c 'source "$1"; PASS=0; FAIL=0; AVISO=0; snmp_confere_real monitorv3 "$2" "$3" 179.125.120.36 2>&1; echo "RES $PASS $FAIL $AVISO"' _ "$RAIZ/baseline-verify.sh" "$SEC_A" "$SEC_P"
}
for CASO in "timeout|Timeout (rede, UFW ou endereço de escuta do snmpd)" "auth|Authentication failure / wrong digest (senha de AUTENTICAÇÃO)" "digest|Authentication failure / wrong digest (senha de AUTENTICAÇÃO)" \
            "decrypt|Decryption error (senha de CRIPTOGRAFIA)" "user|Unknown user name (usuário SNMPv3 errado ou inexistente)"; do
  MODO=${CASO%%|*}; ESPERA=${CASO#*|}
  t "motivo da falha ($MODO): '$ESPERA'" bash -c 'STUB_MODE_127_0_0_1=$1 PATH="$2:$PATH" bash -c "source $3/baseline-verify.sh; snmp_get 127.0.0.1 monitorv3 \"\$1\" \"\$2\"; echo \"\$SNMP_MOTIVO\"" _ "$4" "$5" | grep -qxF -- "$6"' _ "$MODO" "$ST" "$RAIZ" "$SEC_A" "$SEC_P" "$ESPERA"
done
sg ok ok > "$TMP/s1.out"
t "local e IP respondem → 2 OK"                                    grep -q '^RES 2 0 0$' "$TMP/s1.out"
sg ok timeout > "$TMP/s2.out"
t "só o local responde → 'responde local, não no IP — confira o agentAddress e o UFW'" bash -c 'grep -q "^RES 1 1 0$" "$1" && grep -q "snmpget SNMPv3 em 179.125.120.36: responde local, não no IP — confira o agentAddress e o UFW (motivo: Timeout" "$1"' _ "$TMP/s2.out"
sg timeout ok > "$TMP/s3.out"
t "só o IP responde → diz 'responde no IP, não no local'"          bash -c 'grep -q "^RES 1 1 0$" "$1" && grep -q "em 127.0.0.1: Timeout.*(responde no IP, não no local)" "$1"' _ "$TMP/s3.out"
sg auth decrypt > "$TMP/s4.out"
t "os dois falham → um motivo para cada endereço"                  bash -c 'grep -q "^RES 0 2 0$" "$1" && grep -q "em 127.0.0.1: Authentication failure" "$1" && grep -q "em 179.125.120.36: Decryption error" "$1"' _ "$TMP/s4.out"
sg vaza vaza > "$TMP/s5.out"
t "motivo desconhecido que ECOA as senhas: elas são mascaradas (***)" bash -c 'grep -q "motivo não reconhecido: .*\*\*\*" "$1" && ! grep -qF -- "$2" "$1" && ! grep -qF -- "$3" "$1"' _ "$TMP/s5.out" "$SEC_A" "$SEC_P"
cat "$TMP/s1.out" "$TMP/s2.out" "$TMP/s3.out" "$TMP/s4.out" "$TMP/s5.out" > "$TMP/s.todos"
t "nenhuma senha aparece em NENHUMA saída do teste (sucesso, falhas, motivos)" bash -c '! grep -qF -- "$2" "$1" && ! grep -qF -- "$3" "$1"' _ "$TMP/s.todos" "$SEC_A" "$SEC_P"
rm -f "$STUB_SNMP_ARGS"; sg ok ok >/dev/null
t "(d) senhas NÃO vão no argv do snmpget (nem -A/-X/-u/-a/-x)"    bash -c '! grep -qF -- "$2" "$1" && ! grep -qF -- "$3" "$1" && ! grep -qE "(^| )-(A|X|u|a|x|l)( |$)" "$1" && [[ $(wc -l < "$1") == 2 ]]' _ "$STUB_SNMP_ARGS" "$SEC_A" "$SEC_P"
t "(d) as senhas estavam num snmp.conf 0600 (pasta 0700) apontado por SNMPCONFPATH" bash -c 'grep -qx "defAuthPassphrase $1" "$3" && grep -qx "defPrivPassphrase $2" "$3" && [[ $(cat "$4") == 600 && $(cat "$5") == 700 ]]' _ "$SEC_A" "$SEC_P" "$STUB_SNMP_CONF" "$STUB_SNMP_MODE" "$STUB_SNMP_DMODE"
t "(d) o arquivo temporário é apagado logo depois do uso"          bash -c 'd=$(cat "$1"); [[ -n $d && ! -e "$d" ]]' _ "$STUB_SNMP_DIR"
mkdir -p "$TMP/tv"; : > "$TMP/tv/snmp.conf"
t "(d) trap: limpa_v apaga a pasta se o verify morrer no meio"    no_verify 'TMPV=("$1"); limpa_v; [[ ! -e "$1" ]]' "$TMP/tv"
t "(d) política: nenhum snmpget com -A/-X/-u nos scripts"           bash -c '! grep -nE "snmpget[^|#]* -(A|X|u|a|x)( |$)" baseline.sh baseline-verify.sh'
t "(d) política: o verify registra a pasta temporária no trap (EXIT)" bash -c 'grep -q "^trap limpa_v EXIT" baseline-verify.sh && grep -q "TMPV+=(\"\$d\")" baseline-verify.sh'

printf 'abc123\nxyz9\n' > "$TMP/in.senhas"
t "(a) ler_oculto: lê as duas senhas sem eco e preenche as variáveis" bash -c 'source "$1"; { ler_oculto "Senha de AUTENTICAÇÃO (Enter pula): " A; ler_oculto "Senha de CRIPTOGRAFIA: " P; } < "$2" 2> "$3" >/dev/null; [[ $A == abc123 && $P == xyz9 ]]' _ "$RAIZ/baseline-verify.sh" "$TMP/in.senhas" "$TMP/err.senhas"
t "(a) cada pergunta numa linha própria, com '(digitado: N caracteres)' depois" bash -c '
  [[ "$(cat "$1")" == $'"'"'  Senha de AUTENTICAÇÃO (Enter pula): \n  (digitado: 6 caracteres)\n  Senha de CRIPTOGRAFIA: \n  (digitado: 4 caracteres)'"'"' ]]' _ "$TMP/err.senhas"
t "(a) nunca o conteúdo digitado"                                  bash -c '! grep -q "abc123\|xyz9" "$1"' _ "$TMP/err.senhas"
t "(a) Enter vazio pula: '(digitado: 0 caracteres)'"               bash -c 'source "$1"; printf "\n" | { ler_oculto "Senha: " A; } 2>&1 >/dev/null | grep -qx "  (digitado: 0 caracteres)"' _ "$RAIZ/baseline-verify.sh"
t "(a) o verify usa ler_oculto para as duas senhas e o teste nos dois endereços" bash -c 'grep -q "ler_oculto \"Senha de AUTENTICAÇÃO (Enter pula): \" A" baseline-verify.sh && grep -q "ler_oculto \"Senha de CRIPTOGRAFIA: \" P" baseline-verify.sh && grep -q "snmp_confere_real \"\$SU\" \"\$A\" \"\$P\" \"\$V4\"" baseline-verify.sh'

sec "Versão marcada: SHA256SUMS"
t "SHA256SUMS confere com os scripts (regenere: sha256sum baseline.sh baseline-verify.sh > SHA256SUMS)" sha256sum -c --quiet SHA256SUMS
t "texto da release traz os dois sha256" bash -c 'for f in baseline.sh baseline-verify.sh; do h=$(sha256sum "$f" | cut -d" " -f1); grep -q "$h" docs/release-v2.2.0.md || exit 1; done'
t "README aponta para v2.2.0" bash -c 'grep -q "v2.2.0/baseline.sh" README.md && ! grep -q "v2.1.0/baseline" README.md'

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
