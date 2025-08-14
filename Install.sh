#!/bin/sh

# Buat folder kalau tak wujud
mkdir -p /usr/lib/lua/luci/controller
mkdir -p /usr/lib/lua/luci/view/clash_converter

# Download controller
wget -O /usr/lib/lua/luci/controller/clash_converter.lua \
https://raw.githubusercontent.com/Razifadm/ClashConverter/main/usr/lib/lua/luci/controller/clash_converter.lua

# Download view
wget -O /usr/lib/lua/luci/view/clash_converter/index.htm \
https://raw.githubusercontent.com/Razifadm/ClashConverter/main/usr/lib/lua/luci/view/clash_converter/index.htm

# Restart LuCI supaya perubahan terus nampak
/etc/init.d/uhttpd restart

echo "✅ Clash Converter installed & LuCI restarted."
