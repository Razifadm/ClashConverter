module("luci.controller.clash_converter", package.seeall)

local http = require("luci.http")
local fs   = require("nixio.fs")
local util = require("luci.util")
local json = require("luci.jsonc")
local sys  = require("luci.sys")
local tpl  = require("luci.template")

local SAVE_DIR_OPENCLASH = "/etc/openclash/config"
local SAVE_DIR_NIKKI     = "/etc/nikki/profiles"

local HEALTH_URL = "https://www.gstatic.com/generate_204"

local FALLBACK_INTERVAL = 30
local FALLBACK_TIMEOUT  = 800
local FALLBACK_LAZY     = true

local DEFAULT_FINGERPRINT = "chrome"

local function trim(s)
    return tostring(s or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function split_lines(s)
    local t = {}
    s = tostring(s or "")

    for line in s:gmatch("[^\r\n]+") do
        line = trim(line)
        if line ~= "" then
            table.insert(t, line)
        end
    end

    return t
end

local function get_lan_ip()
    local ip = trim(sys.exec("uci get network.lan.ipaddr 2>/dev/null"))
    if ip == "" then ip = "192.168.1.1" end
    return ip
end

local function get_openclash_url()
    return "http://" .. get_lan_ip() .. "/cgi-bin/luci/admin/services/openclash"
end

local function get_nikki_url()
    return "http://" .. get_lan_ip() .. "/cgi-bin/luci/admin/services/nikki"
end

local function url_decode(s)
    if not s then return "" end
    s = tostring(s):gsub("+", " ")
    return s:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
end

local function base64_decode(s)
    if not s then return nil end

    s = tostring(s)
    s = s:gsub("%s+", "")
    s = s:gsub("%-", "+")
    s = s:gsub("_", "/")

    local rem = #s % 4
    if rem > 0 then
        s = s .. string.rep("=", 4 - rem)
    end

    local ok, res = pcall(function()
        return util.base64decode(s)
    end)

    if ok and res and res ~= "" then
        return res
    end

    return nil
end

local function safe_file_name(name)
    name = trim(name)
    if name == "" then name = "clash_config" end

    local s = name
    s = s:gsub("[\r\n\t]", " ")
    s = s:gsub("[^%w%-%._%s]", "-")
    s = s:gsub("%s+", "-")
    s = s:gsub("%-+", "-")
    s = s:gsub("^%-+", "")
    s = s:gsub("%-+$", "")
    s = s:lower()

    if s == "" then s = "clash_config" end
    return s
end

local function safe_node_name(name)
    name = trim(name)
    if name == "" then name = "NODE" end

    local s = name
    s = s:gsub("[\r\n\t]", " ")
    s = s:gsub("[^%w%-%._%s]", "-")
    s = s:gsub("%s+", "-")
    s = s:gsub("%-+", "-")
    s = s:gsub("^%-+", "")
    s = s:gsub("%-+$", "")

    if s == "" then s = "NODE" end
    return s
end

local function yaml_quote(v)
    v = tostring(v or "")
    v = v:gsub("\\", "\\\\")
    v = v:gsub("'", "''")
    return "'" .. v .. "'"
end

local function yaml_bool(v)
    return v and "true" or "false"
end

local function parse_query(qstr)
    local q = {}

    qstr = tostring(qstr or "")
    if qstr == "" then
        return q
    end

    for pair in qstr:gmatch("[^&]+") do
        local k, v = pair:match("^([^=]+)=?(.*)$")
        if k and k ~= "" then
            q[url_decode(k)] = url_decode(v or "")
        end
    end

    return q
end

local function guess_label(name, index)
    local n = tostring(name or ""):lower()

    if n:find("tmnet") or n:find("tm%-") or n:find("tm_") then return "TMnet 🇲🇾" end
    if n:find("shin") then return "SHIN 🇲🇾" end
    if n:find("pq") then return "PQ 🇲🇾" end
    if n:find("kl") or n:find("mykl") then return "KL 🇲🇾" end
    if n:find("do") or n:find("sg3") or n:find("digital") then return "DO 🇸🇬" end
    if n:find("lease") or n:find("ls") then return "Leaseweb 🇸🇬" end
    if n:find("media") or n:find("nmedia") or n:find("nme") then return "NewMedia 🇸🇬" end

    return "NODE " .. tostring(index)
end

local function unique_node_names(nodes)
    local used_names = {}
    local used_labels = {}

    for i, node in ipairs(nodes) do
        local base = safe_node_name(node.name or node.server or ("NODE-" .. tostring(i)))
        local name = base
        local n = 2

        while used_names[name] do
            name = base .. "-" .. tostring(n)
            n = n + 1
        end

        used_names[name] = true
        node.safe_name = name

        local label_base = guess_label(name, i)
        local label = label_base
        local x = 2

        while used_labels[label] do
            label = label_base .. " " .. tostring(x)
            x = x + 1
        end

        used_labels[label] = true
        node.group_label = label
    end

    return nodes
end

local function parse_vless(line)
    local raw = tostring(line or ""):match("^vless://(.+)")
    if not raw then return nil, "Not VLESS" end

    local before_hash, remark = raw:match("^([^#]+)#?(.*)$")
    remark = remark and url_decode(remark) or ""

    local userpart, hostpart = before_hash:match("^([^@]+)@(.+)$")
    if not userpart or not hostpart then
        return nil, "Invalid VLESS format"
    end

    local hostport, qstr = hostpart:match("^([^?]+)%??(.*)$")
    local host, port = hostport:match("^(.-):(%d+)$")
    if not host then host = hostport end

    local q = parse_query(qstr)
    local network = q.type or q.net or "ws"
    local security = q.security or q.tls or ""
    local tls = (security == "tls" or q.tls == "1" or q.tls == "true")

    local sni_val = q.sni or q.servername or q.host or ""
    local ws_host = q.host or sni_val or host or ""
    local path = q.path or q.wsPath or "/"

    local node = {
        raw_type = "vless",
        name = remark ~= "" and remark or q.remark or q.name or host or "VLESS",
        server = host or "",
        port = tonumber(port) or 443,
        uuid = userpart or q.uuid or "",
        encryption = q.encryption or "none",
        tls = tls,
        sni = sni_val,
        servername = sni_val,
        skip_cert_verify = true,
        network = network,
        ws_path = path,
        ws_host = ws_host,
        grpc_service_name = q.serviceName or q["service-name"] or q.grpcServiceName or "",
        flow = q.flow or "",
        client_fingerprint = q.fp or q.fingerprint or DEFAULT_FINGERPRINT,
        alpn = q.alpn or ""
    }

    if node.server == "" or node.uuid == "" then
        return nil, "VLESS missing server/uuid"
    end

    return node
end

local function parse_vmess(line)
    local b64 = tostring(line or ""):match("^vmess://(.+)")
    if not b64 then return nil, "Not VMESS" end

    local decoded = base64_decode(b64)
    if not decoded then
        return nil, "Failed to decode VMESS base64"
    end

    local ok, obj = pcall(function()
        return json.parse(decoded)
    end)

    if not ok or not obj then
        return nil, "Failed to parse VMESS JSON"
    end

    local network = obj.net or obj.type or "ws"
    local tls_raw = tostring(obj.tls or "")
    local tls = tls_raw ~= "" and tls_raw ~= "0" and tls_raw ~= "false"
    local sni_val = obj.sni or obj.host or ""
    local ws_host = obj.host or sni_val or obj.add or ""

    local node = {
        raw_type = "vmess",
        name = obj.ps or obj.tag or obj.remarks or obj.add or obj.host or "VMESS",
        server = obj.add or obj.host or "",
        port = tonumber(obj.port) or 443,
        uuid = obj.id or obj.uuid or "",
        alterId = tonumber(obj.aid) or tonumber(obj.alterId) or 0,
        cipher = obj.scy or obj.cipher or "auto",
        tls = tls,
        sni = sni_val,
        servername = sni_val,
        skip_cert_verify = true,
        network = network,
        ws_path = obj.path or obj.wsPath or "/",
        ws_host = ws_host,
        grpc_service_name = obj.serviceName or obj["service-name"] or obj.grpcServiceName or "",
        client_fingerprint = obj.fp or obj.fingerprint or DEFAULT_FINGERPRINT,
        alpn = obj.alpn or ""
    }

    if node.server == "" or node.uuid == "" then
        return nil, "VMESS missing server/uuid"
    end

    return node
end

local function parse_nodes(input)
    local nodes = {}
    local errors = {}

    for _, line in ipairs(split_lines(input)) do
        local node, err

        if line:match("^vless://") then
            node, err = parse_vless(line)
        elseif line:match("^vmess://") then
            node, err = parse_vmess(line)
        else
            err = "Skipped: not VLESS/VMESS"
        end

        if node then
            table.insert(nodes, node)
        else
            table.insert(errors, {
                line = line,
                error = err or "Unknown error"
            })
        end
    end

    unique_node_names(nodes)
    return nodes, errors
end

local function append_base_config(lines)
    table.insert(lines, "port: 7890")
    table.insert(lines, "socks-port: 7891")
    table.insert(lines, "redir-port: 7892")
    table.insert(lines, "tproxy-port: 7895")
    table.insert(lines, "mixed-port: 7893")
    table.insert(lines, "allow-lan: true")
    table.insert(lines, "mode: rule")
    table.insert(lines, "log-level: silent")
    table.insert(lines, "ipv6: false")
    table.insert(lines, "unified-delay: true")
    table.insert(lines, "tcp-fast-open: true")
    table.insert(lines, "tcp-concurrent: true")
    table.insert(lines, "")

    table.insert(lines, "profile:")
    table.insert(lines, "  store-selected: true")
    table.insert(lines, "  store-fake-ip: true")
    table.insert(lines, "")

    table.insert(lines, "tun:")
    table.insert(lines, "  enable: true")
    table.insert(lines, "  stack: system")
    table.insert(lines, "  auto-route: true")
    table.insert(lines, "  auto-detect-interface: true")
    table.insert(lines, "  strict-route: true")
    table.insert(lines, "  dns-hijack:")
    table.insert(lines, "    - any:53")
    table.insert(lines, "")

    table.insert(lines, "dns:")
    table.insert(lines, "  enable: true")
    table.insert(lines, "  listen: 127.0.0.1:7874")
    table.insert(lines, "  ipv6: false")
    table.insert(lines, "  enhanced-mode: fake-ip")
    table.insert(lines, "  fake-ip-range: 198.18.0.1/16")
    table.insert(lines, "  fake-ip-cache: true")
    table.insert(lines, "  respect-rules: true")
    table.insert(lines, "  use-system-hosts: false")
    table.insert(lines, "  use-hosts: true")
    table.insert(lines, "  fake-ip-filter:")
    table.insert(lines, "    - \"*.lan\"")
    table.insert(lines, "    - \"*.local\"")
    table.insert(lines, "    - \"router.*\"")
    table.insert(lines, "    - \"localhost\"")
    table.insert(lines, "    - \"dns.msftncsi.com\"")
    table.insert(lines, "    - \"captive.apple.com\"")
    table.insert(lines, "    - \"time.apple.com\"")
    table.insert(lines, "    - \"+.msftconnecttest.com\"")
    table.insert(lines, "    - \"+.astro.com.my\"")
    table.insert(lines, "    - \"+.sooka.my\"")
    table.insert(lines, "    - \"+.tonton.com.my\"")
    table.insert(lines, "    - \"+.unifi.com.my\"")
    table.insert(lines, "    - \"+.akamaized.net\"")
    table.insert(lines, "    - \"+.googlevideo.com\"")
    table.insert(lines, "    - \"+.umax.com.my\"")
    table.insert(lines, "    - \"+.dtv.com.my\"")
    table.insert(lines, "  default-nameserver:")
    table.insert(lines, "    - 1.1.1.1")
    table.insert(lines, "    - 8.8.8.8")
    table.insert(lines, "  proxy-server-nameserver:")
    table.insert(lines, "    - 1.1.1.1")
    table.insert(lines, "  nameserver:")
    table.insert(lines, "    - https://1.1.1.1/dns-query")
    table.insert(lines, "    - https://dns.google/dns-query")
    table.insert(lines, "  nameserver-policy:")
    table.insert(lines, "    \"geosite:category-ads-all\": rcode://success")
    table.insert(lines, "    \"*.astro.com.my\": [1.1.1.1, 8.8.8.8]")
    table.insert(lines, "    \"*.sooka.my\": [1.1.1.1, 8.8.8.8]")
    table.insert(lines, "    \"*.tonton.com.my\": [1.1.1.1, 8.8.8.8]")
    table.insert(lines, "    \"**ott**\": [1.1.1.1, 8.8.8.8]")
    table.insert(lines, "    \"**xtream**\": [1.1.1.1, 8.8.8.8]")
    table.insert(lines, "    \"**iptv**\": [1.1.1.1, 8.8.8.8]")
    table.insert(lines, "")

    table.insert(lines, "sniffer:")
    table.insert(lines, "  enable: true")
    table.insert(lines, "  sniff:")
    table.insert(lines, "    TLS: {ports: [443, 8443]}")
    table.insert(lines, "    HTTP: {ports: [80, 8080, 8880, 2052, 2082, 2086, 2095, 25461]}")
    table.insert(lines, "    QUIC: {ports: [443]}")
    table.insert(lines, "  sniff-pure-ip: true")
    table.insert(lines, "  override-destination: false")
    table.insert(lines, "")
end

local function append_proxy(lines, node)
    table.insert(lines, "  - name: " .. yaml_quote(node.safe_name))
    table.insert(lines, "    type: " .. node.raw_type)
    table.insert(lines, "    server: " .. yaml_quote(node.server))
    table.insert(lines, "    port: " .. tostring(node.port or 443))
    table.insert(lines, "    uuid: " .. yaml_quote(node.uuid))

    if node.raw_type == "vmess" then
        table.insert(lines, "    alterId: " .. tostring(node.alterId or 0))
        table.insert(lines, "    cipher: " .. yaml_quote(node.cipher or "auto"))
    end

    if node.raw_type == "vless" then
        table.insert(lines, "    encryption: " .. yaml_quote(node.encryption or "none"))
        if node.flow and node.flow ~= "" then
            table.insert(lines, "    flow: " .. yaml_quote(node.flow))
        end
    end

    table.insert(lines, "    tls: " .. yaml_bool(node.tls))

    local sni_val = node.sni or node.servername or ""
    if sni_val ~= "" then
        table.insert(lines, "    sni: " .. yaml_quote(sni_val))
    end

    table.insert(lines, "    skip-cert-verify: " .. yaml_bool(node.skip_cert_verify))
    table.insert(lines, "    network: " .. yaml_quote(node.network or "ws"))

    if node.network == "ws" then
        table.insert(lines, "    ws-opts:")
        table.insert(lines, "      path: " .. yaml_quote(node.ws_path or "/"))
        table.insert(lines, "      headers:")

        local host_val = node.ws_host
        if not host_val or host_val == "" then host_val = node.sni end
        if not host_val or host_val == "" then host_val = node.servername end
        if not host_val or host_val == "" then host_val = node.server end

        table.insert(lines, "        Host: " .. yaml_quote(host_val))
    elseif node.network == "grpc" then
        table.insert(lines, "    grpc-opts:")
        table.insert(lines, "      grpc-service-name: " .. yaml_quote(node.grpc_service_name or ""))
    end

    table.insert(lines, "    udp: true")
    table.insert(lines, "")
end

local function append_proxies(lines, nodes)
    table.insert(lines, "proxies:")

    for _, node in ipairs(nodes) do
        append_proxy(lines, node)
    end
end

local function ordered_names(nodes, primary_index)
    local names = {}

    table.insert(names, nodes[primary_index].safe_name)

    for i, node in ipairs(nodes) do
        if i ~= primary_index then
            table.insert(names, node.safe_name)
        end
    end

    return names
end

local function append_fallback_group(lines, group_name, proxy_names)
    table.insert(lines, "  - name: " .. yaml_quote(group_name))
    table.insert(lines, "    type: fallback")
    table.insert(lines, "    proxies:")

    for _, name in ipairs(proxy_names) do
        table.insert(lines, "      - " .. yaml_quote(name))
    end

    table.insert(lines, "    url: " .. HEALTH_URL)
    table.insert(lines, "    interval: " .. tostring(FALLBACK_INTERVAL))
    table.insert(lines, "    timeout: " .. tostring(FALLBACK_TIMEOUT))
    table.insert(lines, "    lazy: " .. yaml_bool(FALLBACK_LAZY))
    table.insert(lines, "")
end

local function append_proxy_groups(lines, nodes)
    table.insert(lines, "proxy-groups:")

    table.insert(lines, "  - name: MAIN")
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies:")
    for _, node in ipairs(nodes) do
        table.insert(lines, "      - " .. yaml_quote(node.group_label))
    end
    table.insert(lines, "")

    table.insert(lines, "  - name: OTT/TTshop")
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies:")
    table.insert(lines, "      - OTTProxies")
    for _, node in ipairs(nodes) do
        table.insert(lines, "      - " .. yaml_quote(node.safe_name))
    end
    table.insert(lines, "")

    local all_names = {}
    for _, node in ipairs(nodes) do
        table.insert(all_names, node.safe_name)
    end

    append_fallback_group(lines, "OTTProxies", all_names)

    for i, node in ipairs(nodes) do
        append_fallback_group(lines, node.group_label, ordered_names(nodes, i))
    end

    table.insert(lines, "  - name: 🛑Ads🛑")
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies: [DIRECT, REJECT]")
    table.insert(lines, "")

    table.insert(lines, "  - name: 🔞Adult🔞")
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies: [DIRECT, REJECT]")
    table.insert(lines, "")
end

local function append_rule_providers(lines)
    table.insert(lines, "rule-providers:")
    table.insert(lines, "  🛑Ads🛑:")
    table.insert(lines, "    type: http")
    table.insert(lines, "    behavior: domain")
    table.insert(lines, "    url: https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml")
    table.insert(lines, "    interval: 86400")
    table.insert(lines, "    path: ./rule_provider/Ads.yaml")
    table.insert(lines, "")
    table.insert(lines, "  🕵Tracking🕵:")
    table.insert(lines, "    type: http")
    table.insert(lines, "    behavior: domain")
    table.insert(lines, "    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Tracking/Tracking.yaml")
    table.insert(lines, "    interval: 86400")
    table.insert(lines, "    path: ./rule_provider/Tracking.yaml")
    table.insert(lines, "")
    table.insert(lines, "  ☣Malware☣:")
    table.insert(lines, "    type: http")
    table.insert(lines, "    behavior: domain")
    table.insert(lines, "    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Malware/Malware.yaml")
    table.insert(lines, "    interval: 86400")
    table.insert(lines, "    path: ./rule_provider/Malware.yaml")
    table.insert(lines, "")
    table.insert(lines, "  🔞Adult🔞:")
    table.insert(lines, "    type: http")
    table.insert(lines, "    behavior: domain")
    table.insert(lines, "    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Adult/Adult.yaml")
    table.insert(lines, "    interval: 86400")
    table.insert(lines, "    path: ./rule_provider/Adult.yaml")
    table.insert(lines, "")
end

local function append_rules(lines)
    table.insert(lines, "rules:")
    table.insert(lines, "  # --- SECURITY ---")
    table.insert(lines, "  - RULE-SET,🛑Ads🛑,🛑Ads🛑")
    table.insert(lines, "  - RULE-SET,🕵Tracking🕵,REJECT")
    table.insert(lines, "  - RULE-SET,☣Malware☣,REJECT")
    table.insert(lines, "  - RULE-SET,🔞Adult🔞,🔞Adult🔞")
    table.insert(lines, "")
    table.insert(lines, "  # --- CRITICAL IPTV ---")
    table.insert(lines, "  - DST-PORT,8080,OTT/TTshop")
    table.insert(lines, "  - DST-PORT,8880,OTT/TTshop")
    table.insert(lines, "  - DST-PORT,25461,OTT/TTshop")
    table.insert(lines, "  - DST-PORT,2095,OTT/TTshop")
    table.insert(lines, "  - DST-PORT,2082,OTT/TTshop")
    table.insert(lines, "  - DST-PORT,2086,OTT/TTshop")
    table.insert(lines, "  - DST-PORT,2052,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,ott,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,ott-navigator,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,xtream,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,iptv,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,playlist,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,m3u8,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,ts,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,live,OTT/TTshop")
    table.insert(lines, "  - PROCESS-NAME,*ott*,OTT/TTshop")
    table.insert(lines, "  - PROCESS-NAME,*tvplayer*,OTT/TTshop")
    table.insert(lines, "  - PROCESS-NAME,*tivimate*,OTT/TTshop")
    table.insert(lines, "  - PROCESS-NAME,*iptv*,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- BANKS & E-WALLETS ---")
    table.insert(lines, "  - DOMAIN-SUFFIX,maybank2u.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,maybank.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,cimbclicks.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,cimb.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,pbebank.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,publicbank.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,rhbgroup.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hongleongconnect.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hlb.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,ambank.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,bankislam.biz,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,bankislam.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,bsn.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,tngdigital.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,touchngo.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,grab.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,shopeepay.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,boostpay.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,fpx.com.my,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- TELCO APPS ---")
    table.insert(lines, "  - DOMAIN-SUFFIX,celcom.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,digi.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,celcomdigi.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,maxis.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hotlink.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,u.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,yes.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,celcom,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,maxis,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,umobile,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- EDUCATION & TEACHER PORTALS ---")
    table.insert(lines, "  - DOMAIN-SUFFIX,moe.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,delima.edu.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,idme.moe.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,sapsnkra.moe.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,eprestasi.moe.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,splkpm.moe.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,apdm.moe.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hrmis2.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,sps.moe.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,moe-dl.edu.my,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- Astro / sooka / NJOI ---")
    table.insert(lines, "  - DOMAIN-SUFFIX,astro.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,astrogo.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,astrogx.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,astrogxcdn.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,sooka.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,stadiumastro.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,umax.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,dtv.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,akamaihd.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,akamaized.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,circle.broadcom.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,vudu.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,conviva.com,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- TikTok Full Routing ---")
    table.insert(lines, "  - DOMAIN-KEYWORD,tiktok,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,tiktok.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,tiktokcdn.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,tiktokcdn-us.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,byteoversea.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,bytedance.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,ibytedtos.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,ibytedtos.com.cdn.cloudflare.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,muscdn.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,tiktokshop.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,tiktokshop,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,shop.tiktok,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,seller.tiktok,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-KEYWORD,buy.itiktokcdn,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- Unifi TV / tonton / RTM ---")
    table.insert(lines, "  - DOMAIN-SUFFIX,unifi.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,playtv.unifi.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,tonton.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,mptv.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,xtra.com.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,rtm.gov.my,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,rtmklik.rtm.gov.my,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- Global OTT ---")
    table.insert(lines, "  - DOMAIN-SUFFIX,netflix.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,netflix.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,nflxvideo.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,nflximg.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,nflxso.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,nflxext.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,disneyplus.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,disney-plus.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,disney-portal.my.id,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,bamgrid.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,primevideo.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,amazonvideo.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,pv-cdn.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hotstar.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hotstar.imgix.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,viu.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hbo.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hbomax.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,hbomaxcdn.com,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- Streaming CDNs ---")
    table.insert(lines, "  - DOMAIN-SUFFIX,googlevideo.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,gvt1.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,gvt2.com,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,edgekey.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,edgesuite.net,OTT/TTshop")
    table.insert(lines, "  - DOMAIN-SUFFIX,cloudfront.net,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- Leak Blocks ---")
    table.insert(lines, "  - DOMAIN,wpad,REJECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,wpad,REJECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,ntp.org,REJECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,time.apple.com,REJECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,msftncsi.com,REJECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,captive.apple.com,REJECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,clients3.google.com,REJECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,connectivitycheck.gstatic.com,REJECT")
    table.insert(lines, "")
    table.insert(lines, "  # --- GEOIP MY ---")
    table.insert(lines, "  - GEOIP,MY,OTT/TTshop")
    table.insert(lines, "")
    table.insert(lines, "  # --- Defaults ---")
    table.insert(lines, "  - IP-CIDR,198.18.0.0/16,MAIN")
    table.insert(lines, "  - IP-CIDR,::/0,REJECT")
    table.insert(lines, "  - MATCH,MAIN")
end

local function build_yaml(nodes)
    local lines = {}

    append_base_config(lines)
    append_proxies(lines, nodes)
    append_proxy_groups(lines, nodes)
    append_rule_providers(lines)
    append_rules(lines)

    return table.concat(lines, "\n") .. "\n"
end

local function ensure_dir(path)
    if not fs.access(path) then
        fs.mkdirr(path)
    end
end

local function unique_filename(dir, base, overwrite)
    ensure_dir(dir)

    base = safe_file_name(base or "clash_config")
    local fname = string.format("%s/%s.yaml", dir, base)

    if overwrite then return fname end
    if not fs.stat(fname) then return fname end

    local i = 1
    while fs.stat(string.format("%s/%s_%d.yaml", dir, base, i)) do
        i = i + 1
    end

    return string.format("%s/%s_%d.yaml", dir, base, i)
end

local function get_save_dir(target)
    target = tostring(target or "openclash")

    if target == "nikki" then
        return SAVE_DIR_NIKKI
    end

    return SAVE_DIR_OPENCLASH
end

local function save_config(target, name_base, content, overwrite)
    local dir = get_save_dir(target)
    local fname = unique_filename(dir, name_base, overwrite)

    local ok, err = pcall(function()
        fs.writefile(fname, content)
    end)

    if not ok then return nil, err end
    return fname
end

function index()
    entry({"admin", "services", "clash_converter"}, call("action_index"), _("OC Converter"), 90).dependent = true
    entry({"admin", "services", "clash_converter", "generate"}, call("action_generate"), nil).leaf = true
    entry({"admin", "services", "clash_converter", "save"}, call("action_save"), nil).leaf = true
end

function action_index()
    tpl.render("clash_converter/index", {
        openclash_url = get_openclash_url(),
        nikki_url = get_nikki_url()
    })
end

function action_generate()
    http.prepare_content("application/json")

    local input = http.formvalue("links") or ""

    if trim(input) == "" then
        http.write_json({
            status = "error",
            msg = "VLESS/VMESS input is empty"
        })
        return
    end

    local nodes, errors = parse_nodes(input)

    if #nodes == 0 then
        http.write_json({
            status = "error",
            msg = "No valid node found",
            errors = errors
        })
        return
    end

    local yaml = build_yaml(nodes)
    local node_names = {}

    for _, node in ipairs(nodes) do
        table.insert(node_names, node.safe_name)
    end

    http.write_json({
        status = "ok",
        yaml = yaml,
        count = #nodes,
        nodes = node_names,
        errors = errors
    })
end

function action_save()
    http.prepare_content("application/json")

    local yaml_input = http.formvalue("yaml_input") or ""
    local name_base = http.formvalue("name_base") or "clash_config"
    local overwrite = http.formvalue("overwrite") == "1"
    local target = http.formvalue("target") or "openclash"

    if trim(yaml_input) == "" then
        http.write_json({
            status = "error",
            msg = "YAML is empty"
        })
        return
    end

    local fname, err = save_config(target, name_base, yaml_input, overwrite)

    if not fname then
        http.write_json({
            status = "error",
            msg = tostring(err)
        })
        return
    end

    http.write_json({
        status = "ok",
        path = fname
    })
end
