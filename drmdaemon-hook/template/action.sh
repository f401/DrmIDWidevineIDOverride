#!/system/bin/sh
MODID="drmdaemon-hook"
if pm path io.github.a13e300.ksuwebui >/dev/null 2>&1; then
  am start -n io.github.a13e300.ksuwebui/.WebUIActivity -e id "$MODID"
elif pm path com.dergoogler.mmrl >/dev/null 2>&1; then
  am start -n com.dergoogler.mmrl/.ui.activity.webui.WebUIActivity -e MOD_ID "$MODID"
elif pm path com.dergoogler.mmrl.webuix >/dev/null 2>&1; then
  am start -n com.dergoogler.mmrl.webuix/.ui.activity.webui.WebUIActivity -e MOD_ID "$MODID"
else
  echo "No compatible WebUI host found"
  exit 1
fi
