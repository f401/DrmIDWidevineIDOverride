MODDIR=${0%/*}
mkdir -p /data/adb/modules/drmdaemon-hook/config
[ -f /data/adb/modules/drmdaemon-hook/config/targets.conf ] || cp "$MODDIR/config/targets.conf" /data/adb/modules/drmdaemon-hook/config/targets.conf
chmod 0644 /data/adb/modules/drmdaemon-hook/config/targets.conf
