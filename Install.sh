#!/bin/sh

echo "installing Clash Converter...."

# Buat folder kalau tak wujud
mkdir -p /usr/lib/lua/luci/controller >/dev/null 2>&1
mkdir -p /usr/lib/lua/luci/view/clash_converter >/dev/null 2>&1

# Download controller
wget -O /usr/lib/lua/luci/controller/clash_converter.lua \
https://raw.githubusercontent.com/Razifadm/ClashConverter/main/usr/lib/lua/luci/controller/clash_converter.lua >/dev/null 2>&1

# Download view
wget -O /usr/lib/lua/luci/view/clash_converter/index.htm \
https://raw.githubusercontent.com/Razifadm/ClashConverter/main/usr/lib/lua/luci/view/clash_converter/index.htm >/dev/null 2>&1

# Restart LuCI supaya perubahan terus nampak
/etc/init.d/uhttpd restart >/dev/null 2>&1

echo "✅ Clash Converter installed & LuCI restarted."
# Padam skrip ini sendiri
rm -f "$0"
