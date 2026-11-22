#!/bin/bash
set -euo pipefail

: "${HSE_PROXY_SERVER:=libtest.hse.ru}"
: "${HSE_PROXY_PORT:=3128}"
: "${HSE_LIST_URL:=https://${HSE_PROXY_SERVER}/www.txt}"
: "${HSE_TEST_URL:=https://www.jstor.org/}"
: "${HSE_KEYCHAIN_LABEL:=HSE Library Proxy}"
: "${HSE_PAC_PATH:=${HOME}/Library/Application Support/HSE Library/hse-library.pac}"
: "${HSE_PAC_URL:=http://127.0.0.1:8642/hse-library.pac}"

for _cfg in /etc/hse-library.conf "${XDG_CONFIG_HOME:-$HOME/.config}/hse-library.conf"; do
  # shellcheck disable=SC1090
  [ -r "$_cfg" ] && . "$_cfg" || true
done

PROXY_HOST="${HSE_PROXY_SERVER}:${HSE_PROXY_PORT}"
PAC_DIR="$(dirname "$HSE_PAC_PATH")"

die() { printf '%s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "Не найдена утилита: $1"; }

valid_host() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

active_services() {
  local svc
  networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\* //' \
  | while IFS= read -r svc; do
      [ -z "$svc" ] && continue
      if networksetup -getinfo "$svc" 2>/dev/null | grep -Eq '^IP address: [0-9]+\.'; then
        printf '%s\n' "$svc"
      fi
    done
}

kc_account() {
  security find-internet-password -s "$HSE_PROXY_SERVER" -l "$HSE_KEYCHAIN_LABEL" 2>/dev/null \
    | sed -n 's/^[[:space:]]*"acct"<blob>="\(.*\)"$/\1/p'
}
kc_password() {
  security find-internet-password -s "$HSE_PROXY_SERVER" -l "$HSE_KEYCHAIN_LABEL" -w 2>/dev/null
}

generate_pac() {
  require curl
  local tmp count
  tmp="$(mktemp "${TMPDIR:-/tmp}/hse-list.XXXXXX")"
  trap 'rm -f "$tmp"; trap - RETURN' RETURN

  curl -fsS --proto '=https' --max-time 30 "$HSE_LIST_URL" -o "$tmp" \
    || die "Не удалось загрузить список доменов с $HSE_LIST_URL"

  mkdir -p "$PAC_DIR"
  chmod 700 "$PAC_DIR"

  count="$(awk -v proxy="$PROXY_HOST" -v out="$HSE_PAC_PATH" '
    function emit(s){ print s > out }
    {
      gsub(/\r/,""); gsub(/^[ \t]+|[ \t]+$/,"")
      if ($0=="") next
      d=tolower($0)
      if (d !~ /^\.?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/) { next }   
      if (seen[d]++) next
      if (substr(d,1,1)==".") { sfx[++ns]=substr(d,2) } else { ex[++ne]=d }
    }
    END {
      emit("// HSE Library PAC — сгенерировано, не редактировать вручную")
      emit("// domains: " (ne+ns))
      emit("var P=\"PROXY " proxy "\";")
      printf "var EXACT={" > out
      for (i=1;i<=ne;i++) printf "%s\"%s\":1",(i>1?",":""),ex[i] > out
      print "};" > out
      printf "var SUF=[" > out
      for (i=1;i<=ns;i++) printf "%s\"%s\"",(i>1?",":""),sfx[i] > out
      print "];" > out
      emit("function hse_match(h){")
      emit("  if (EXACT[h]) return true;")
      emit("  for (var i=0;i<SUF.length;i++){var s=SUF[i];")
      emit("    if (h===s || (h.length>s.length && h.slice(-(s.length+1))===(\".\"+s))) return true;")
      emit("  }")
      emit("  return false;")
      emit("}")
      emit("function FindProxyForURL(url,host){ host=(\"\"+host).toLowerCase(); return hse_match(host)?P:\"DIRECT\"; }")
      print (ne+ns)
    }
  ' "$tmp")"

  chmod 644 "$HSE_PAC_PATH"
  [ "${count:-0}" -gt 0 ] || die "Список доменов пуст или невалиден."
  printf '%s\n' "Сгенерирован PAC: $count ресурсов."
}

cmd_on() {
  require networksetup
  generate_pac
  local svc found=0
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    found=1
    networksetup -setautoproxyurl "$svc" "$HSE_PAC_URL" \
      || die "Не удалось задать PAC для «${svc}» (нужны права администратора?)."
    networksetup -setautoproxystate "$svc" on \
      || die "Не удалось включить прокси для «${svc}»."
    printf '%s\n' "Прокси включен для «${svc}»."
  done < <(active_services)
  [ "$found" = 1 ] || die "Нет активных сетевых служб."
}

cmd_off() {
  require networksetup
  local svc found=0
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    found=1
    networksetup -setautoproxystate "$svc" off \
      || die "Не удалось отключить прокси для «${svc}»."
    printf '%s\n' "Прокси отключен для «${svc}»."
  done < <(active_services)
  [ "$found" = 1 ] || printf '%s\n' "Активных сетевых служб не найдено."
}

cmd_test() {
  require security; require curl
  local acct pw code
  acct="$(kc_account)"; [ -n "$acct" ] || die "Учетные данные не сохранены. Войдите через приложение."
  pw="$(kc_password)";  [ -n "$pw" ]   || die "Не удалось прочитать пароль из связки ключей."

  code="$(printf 'proxy-user = "%s:%s"\n' "$acct" "$pw" \
    | curl -K - -x "http://$PROXY_HOST" -sS -o /dev/null -w '%{http_code}' \
        --max-time 20 "$HSE_TEST_URL")" || code="000"
  pw=""

  case "$code" in
    2*|3*)  printf '%s\n' "Пользуйтесь ресурсами ВШЭ!" ;;
    407)    printf '%s\n' "Логин или пароль для «${acct}» неверны." ;;
    000|"") die "Сервер не отвечает (проверьте сеть/прокси)." ;;
    *)      die "Ошибка: HTTP ${code}" ;;
  esac
}

cmd_check() {
  local host="${1:-}"
  [ -n "$host" ] || die "Использование: check <host>"
  host="${host#http://}"; host="${host#https://}"; host="${host%%/*}"
  valid_host "$host" || die "Недопустимое имя хоста: $host"

  local routed="нет"
  if [ -f "$HSE_PAC_PATH" ] && grep -Eq "\"$host\"|\.${host#*.}" "$HSE_PAC_PATH" 2>/dev/null; then
    routed="да"
  fi

  local acct pw code
  acct="$(kc_account)"; pw="$(kc_password)"
  if [ -n "$acct" ] && [ -n "$pw" ]; then
    code="$(printf 'proxy-user = "%s:%s"\n' "$acct" "$pw" \
      | curl -K - -x "http://$PROXY_HOST" -sS -o /dev/null -I -w '%{http_code}' \
          --max-time 20 "https://$host/")" || code="000"
    pw=""
  else
    code="—"
  fi

  printf '%s\n' "Хост: $host"
  printf '%s\n' "В списке ВШЭ: $routed"
  case "$code" in
    2*|3*) printf '%s\n' "Через прокси: доступен (HTTP $code)" ;;
    407)   printf '%s\n' "Через прокси: требуется верный логин/пароль (407)" ;;
    000)   printf '%s\n' "Через прокси: недоступен" ;;
    —)     printf '%s\n' "Через прокси: не проверено (нет учетных данных)" ;;
    *)     printf '%s\n' "Через прокси: HTTP $code" ;;
  esac
}

cmd_status() {
  require networksetup
  local svc n
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    printf '%s\n' "Служба: $svc"
    networksetup -getautoproxyurl "$svc" 2>/dev/null | sed 's/^/  /'
  done < <(active_services)
  if [ -f "$HSE_PAC_PATH" ]; then
    n="$(awk -F': ' '/^\/\/ domains:/{print $2; exit}' "$HSE_PAC_PATH")"
    printf '%s\n' "PAC: $HSE_PAC_PATH (${n:-0} ресурсов)"
  else
    printf '%s\n' "PAC: не сгенерирован"
  fi
}

case "${1:-}" in
  on)     cmd_on ;;
  off)    cmd_off ;;
  update) generate_pac ;;
  test)   cmd_test ;;
  check)  shift; cmd_check "${1:-}" ;;
  status) cmd_status ;;
  *)      die "Использование: $(basename "$0") {on|off|update|test|check <host>|status}" ;;
esac
