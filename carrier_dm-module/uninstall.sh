#!/system/bin/sh
# 卸载时清理三家规则
MODDIR=${0%/*}
for p in com.mobiletools.systemhelper com.coloros.regservice com.oppo.ctautoregist; do
  u=$(cat "$MODDIR/uid/$p.uid" 2>/dev/null)
  [ -z "$u" ] && u=$(stat -c %u "/data/user/0/$p" 2>/dev/null)
  [ -n "$u" ] || continue
  iptables  -D OUTPUT -m owner --uid-owner "$u" -j REJECT 2>/dev/null
  ip6tables -D OUTPUT -m owner --uid-owner "$u" -j REJECT 2>/dev/null
done
