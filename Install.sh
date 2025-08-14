#!/bin/sh

# Fail controller
wget -O /usr/lib/lua/luci/controller/clash_converter.lua \
https://raw.githubusercontent.com/Razifadm/ClashConverter/main/usr/lib/lua/luci/controller/clash_converter.lua

# Fail view
mkdir -p /usr/lib/lua/luci/view/clash_converter
wget -O /usr/lib/lua/luci/view/clash_converter/index.htm \
https://raw.githubusercontent.com/Razifadm/ClashConverter/main/usr/lib/lua/luci/view/clash_converter/index.htm

echo "✅ Clash Converter installed. Restart LuCI to apply changes."
