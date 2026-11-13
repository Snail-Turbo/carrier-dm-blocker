#!/system/bin/sh
# 早期阶段只记录，不阻塞开机
MODDIR=${0%/*}
echo "[$(date '+%F %T')] post-fs-data: carrier_dm_blocker loaded" >> "$MODDIR/log.txt" 2>/dev/null
