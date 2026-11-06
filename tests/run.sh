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
