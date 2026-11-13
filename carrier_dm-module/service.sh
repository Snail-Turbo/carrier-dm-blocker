#!/system/bin/sh
############################################################
# 运营商 DM 出站阻断  v1.0（三家合集）
#   联通 com.mobiletools.systemhelper
#   移动 com.coloros.regservice        （PMS 层隐藏，界面查不到）
#   电信 com.oppo.ctautoregist
#
#   手段: iptables/ip6tables 按 uid + owner 匹配 -> REJECT
#         + 开机用 dbfix.dex 直接写 LSPosed 的 scope 表
############################################################

MODDIR=${0%/*}
LOG="$MODDIR/log.txt"
UIDDIR="$MODDIR/uid"
XMOD=com.example.carrierdmblocker

PKG_UNICOM=com.mobiletools.systemhelper
PKG_CMCC=com.coloros.regservice
PKG_CT=com.oppo.ctautoregist
PKGS="$PKG_UNICOM $PKG_CMCC $PKG_CT"

mkdir -p "$UIDDIR" 2>/dev/null

log() { echo "[$(date '+%F %T')] $*" >> "$LOG" 2>/dev/null; }
have() { command -v "$1" >/dev/null 2>&1; }

parse_pm() {
  sed -n 's/.*uid:\([0-9]\{1,\}\).*/\1/p' | head -1
}

detect_uid() {
  pkg="$1"
  u=""
  have pm && u=$(pm list packages -U 2>/dev/null | grep -F "package:$pkg " | parse_pm)
  [ -z "$u" ] && have cmd && u=$(cmd package list packages -U 2>/dev/null | grep -F "package:$pkg " | parse_pm)
  [ -z "$u" ] && u=$(dumpsys package "$pkg" 2>/dev/null | grep -o 'appId=[0-9]*' | head -1 | cut -d= -f2)
  [ -z "$u" ] && u=$(stat -c %u "/data/user/0/$pkg" 2>/dev/null)
  [ -z "$u" ] && u=$(stat -c %u "/data/data/$pkg" 2>/dev/null)
  if [ -z "$u" ] && [ -f /data/system/packages.list ]; then
    u=$(grep "^$pkg " /data/system/packages.list 2>/dev/null | awk '{print $2}')
  fi
  case "$u" in ''|*[!0-9]*) u="" ;; esac
  if [ -n "$u" ] && [ "$u" -lt 10000 ]; then u=""; fi
  echo "$u"
}

uid_of() { cat "$UIDDIR/$1.uid" 2>/dev/null; }

store_uid() {
  u=$(detect_uid "$1")
  if [ -n "$u" ]; then
    echo "$u" > "$UIDDIR/$1.uid"
  fi
  echo "$u"
}

apply_rules() {
  uid="$1"
  if have iptables; then
    iptables -D OUTPUT -m owner --uid-owner "$uid" -j REJECT 2>/dev/null
    iptables -I OUTPUT -m owner --uid-owner "$uid" -j REJECT 2>/dev/null \
      || log "  iptables 添加失败 uid=$uid"
  fi
  if have ip6tables; then
    ip6tables -D OUTPUT -m owner --uid-owner "$uid" -j REJECT 2>/dev/null
    ip6tables -I OUTPUT -m owner --uid-owner "$uid" -j REJECT 2>/dev/null \
      || log "  ip6tables 添加失败 uid=$uid"
  fi
  return 0
}

rules_ok() {
  uid="$1"
  if have iptables && ! iptables -S OUTPUT 2>/dev/null | grep -q -- "--uid-owner $uid"; then
    return 1
  fi
  if have ip6tables && ! ip6tables -S OUTPUT 2>/dev/null | grep -q -- "--uid-owner $uid"; then
    return 1
  fi
  return 0
}

# ---------- 等开机完成 ----------
log "service: waiting for boot_completed"
i=0
while [ "$(getprop sys.boot_completed)" != "1" ] && [ $i -lt 120 ]; do
  sleep 5; i=$((i+1))
done
sleep 20

# ---------- LSPosed scope 自愈 ----------
heal_scope() {
  [ -f "$MODDIR/dbfix.dex" ] || { log "scope: 缺 dbfix.dex，跳过"; return; }
  dumpsys package "$XMOD" >/dev/null 2>&1 || { log "scope: Xposed 模块未安装，跳过"; return; }
  OUT=$(CLASSPATH="$MODDIR/dbfix.dex" app_process /system/bin com.rgs.DbFix 2>&1)
  case "$OUT" in
    *"ERROR"*) log "scope: 读库失败 $(echo "$OUT" | grep ERROR | head -1)" ;;
    *"added"*) log "scope: 已补写 $(echo "$OUT" | grep -c '^added') 条" ;;
    *)         log "scope: 已是完整状态" ;;
  esac
}
heal_scope

# ---------- 逐个目标探测 uid + 加规则 ----------
n=0
while [ $n -lt 20 ]; do
  missing=""
  for p in $PKGS; do
    u=$(store_uid "$p")
    [ -z "$u" ] && missing="$missing $p"
  done
  [ -z "$missing" ] && break
  n=$((n+1))
  log "第 $n 轮仍有目标没取到 uid:$missing（15 秒后重试）"
  sleep 15
done

for p in $PKGS; do
  u=$(uid_of "$p")
  if [ -n "$u" ]; then
    log "target $p uid=$u"
    apply_rules "$u"
  else
    log "skip $p（没有 uid，可能未安装）"
  fi
done

# ---------- 共享配置目录 ----------
for p in $PKGS; do
  mkdir -p "/storage/emulated/0/Android/media/$p/SHBlocker" 2>/dev/null
done

# ---------- 60 秒自愈 ----------
while true; do
  sleep 60
  for p in $PKGS; do
    u=$(uid_of "$p")
    if [ -z "$u" ]; then
      u=$(store_uid "$p")
    fi
    [ -z "$u" ] && continue
    if ! rules_ok "$u"; then
      log "rules missing -> re-apply $p（uid=$u）"
      apply_rules "$u"
    fi
  done
done
