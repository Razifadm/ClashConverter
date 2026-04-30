module("luci.controller.clash_converter", package.seeall)

local http = require("luci.http")
local fs   = require("nixio.fs")
local util = require("luci.util")
local json = require("luci.jsonc")
local sys  = require("luci.sys")
local tpl  = require("luci.template")

local SAVE_DIR_OPENCLASH = "/etc/openclash/config"
local SAVE_DIR_NIKKI     = "/etc/nikki/profiles"

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

local function safe_name_raw(name)
    name = trim(name)

    if name == "" then
        name = "node"
    end

    local s = name
    s = s:gsub("[\r\n\t]", " ")
    s = s:gsub("^%s+", "")
    s = s:gsub("%s+$", "")
    s = s:gsub("[^%w%-%._%s]", "-")
    s = s:gsub("%s+", "-")
    s = s:gsub("%-+", "-")
    s = s:lower()

    if s == "" then
        s = "node"
    end

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

local function unique_node_names(nodes)
    local used = {}

    for _, node in ipairs(nodes) do
        local base = safe_name_raw(node.name or node.server or node.raw_type or "node")
        local name = base
        local i = 2

        while used[name] do
            name = base .. "-" .. tostring(i)
            i = i + 1
        end

        used[name] = true
        node.safe_name = name
    end

    return nodes
end

local function parse_vless(line)
    local raw = tostring(line or ""):match("^vless://(.+)")
    if not raw then
        return nil, "Bukan VLESS"
    end

    local before_hash, remark = raw:match("^([^#]+)#?(.*)$")
    remark = remark and url_decode(remark) or ""

    local userpart, hostpart = before_hash:match("^([^@]+)@(.+)$")
    if not userpart or not hostpart then
        return nil, "Format VLESS tidak valid"
    end

    local hostport, qstr = hostpart:match("^([^?]+)%??(.*)$")
    local host, port = hostport:match("^(.-):(%d+)$")

    if not host then
        host = hostport
    end

    local q = parse_query(qstr)

    local network = q.type or q.net or "ws"
    local security = q.security or q.tls or ""

    local node = {
        raw_type = "vless",
        name = remark ~= "" and remark or q.remark or q.name or host or "vless-node",
        server = host or "",
        port = tonumber(port) or 443,
        uuid = userpart or q.uuid or "",
        tls = (security == "tls" or q.tls == "1" or q.tls == "true"),
        skip_cert_verify = true,
        servername = q.sni or q.servername or q.host or "",
        network = network,

        udp = true,
        tfo = true,

        ws_path = q.path or q.wsPath or "/",
        ws_host = q.host or "",

        grpc_service_name = q.serviceName or q["service-name"] or q.grpcServiceName or "",

        flow = q.flow or "",
        encryption = q.encryption or "none",
        client_fingerprint = q.fp or q.fingerprint or "chrome",
        alpn = q.alpn or ""
    }

    if node.server == "" or node.uuid == "" then
        return nil, "VLESS kurang server/uuid"
    end

    return node
end

local function parse_vmess(line)
    local b64 = tostring(line or ""):match("^vmess://(.+)")
    if not b64 then
        return nil, "Bukan VMESS"
    end

    local decoded = base64_decode(b64)
    if not decoded then
        return nil, "Gagal decode VMESS base64"
    end

    local ok, obj = pcall(function()
        return json.parse(decoded)
    end)

    if not ok or not obj then
        return nil, "Gagal parse JSON VMESS"
    end

    local network = obj.net or obj.type or "ws"
    local tls_raw = tostring(obj.tls or "")

    local node = {
        raw_type = "vmess",
        name = obj.ps or obj.tag or obj.remarks or obj.add or obj.host or "vmess-node",
        server = obj.add or obj.host or "",
        port = tonumber(obj.port) or 443,
        uuid = obj.id or obj.uuid or "",
        alterId = tonumber(obj.aid) or tonumber(obj.alterId) or 0,
        cipher = obj.scy or obj.cipher or "auto",
        tls = tls_raw ~= "" and tls_raw ~= "0" and tls_raw ~= "false",
        skip_cert_verify = true,
        servername = obj.sni or obj.host or "",
        network = network,

        udp = true,
        tfo = true,

        ws_path = obj.path or obj.wsPath or "/",
        ws_host = obj.host or "",

        grpc_service_name = obj.serviceName or obj["service-name"] or obj.grpcServiceName or "",

        client_fingerprint = obj.fp or obj.fingerprint or "chrome",
        alpn = obj.alpn or ""
    }

    if node.server == "" or node.uuid == "" then
        return nil, "VMESS kurang server/uuid"
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
            err = "Skip: bukan VLESS/VMESS"
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

local function append_base_config(lines, opts)
    opts = opts or {}

    local unified_delay = opts.unified_delay ~= false
    local tcp_concurrent = opts.tcp_concurrent ~= false
    local global_fingerprint = opts.global_fingerprint or "chrome"

    table.insert(lines, "port: 7890")
    table.insert(lines, "socks-port: 7891")
    table.insert(lines, "redir-port: 7892")
    table.insert(lines, "mixed-port: 7893")
    table.insert(lines, "tproxy-port: 7895")
    table.insert(lines, "allow-lan: true")
    table.insert(lines, "bind-address: '*'")
    table.insert(lines, "mode: rule")
    table.insert(lines, "log-level: silent")
    table.insert(lines, "ipv6: false")

    table.insert(lines, "unified-delay: " .. yaml_bool(unified_delay))
    table.insert(lines, "tcp-fast-open: true")
    table.insert(lines, "tcp-concurrent: " .. yaml_bool(tcp_concurrent))
    table.insert(lines, "find-process-mode: strict")
    table.insert(lines, "global-client-fingerprint: " .. yaml_quote(global_fingerprint))

    table.insert(lines, "external-controller: 0.0.0.0:9090")
    table.insert(lines, "secret: ''")
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

    table.insert(lines, "sniffer:")
    table.insert(lines, "  enable: true")
    table.insert(lines, "  sniff:")
    table.insert(lines, "    TLS:")
    table.insert(lines, "      ports:")
    table.insert(lines, "        - 443")
    table.insert(lines, "        - 8443")
    table.insert(lines, "    HTTP:")
    table.insert(lines, "      ports:")
    table.insert(lines, "        - 80")
    table.insert(lines, "        - 8080-8880")
    table.insert(lines, "      override-destination: true")
    table.insert(lines, "  sniffing:")
    table.insert(lines, "    - tls")
    table.insert(lines, "    - http")
    table.insert(lines, "  force-domain:")
    table.insert(lines, "    - +.speedtest.net")
    table.insert(lines, "    - +.ookla.com")
    table.insert(lines, "    - +.ooklaserver.net")
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
    table.insert(lines, "  default-nameserver:")
    table.insert(lines, "    - 1.1.1.1")
    table.insert(lines, "    - 8.8.8.8")
    table.insert(lines, "  proxy-server-nameserver:")
    table.insert(lines, "    - 1.1.1.1")
    table.insert(lines, "    - 8.8.8.8")
    table.insert(lines, "  nameserver:")
    table.insert(lines, "    - https://1.1.1.1/dns-query")
    table.insert(lines, "    - https://dns.google/dns-query")
    table.insert(lines, "  fallback:")
    table.insert(lines, "    - https://cloudflare-dns.com/dns-query")
    table.insert(lines, "    - https://dns.google/dns-query")
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
    table.insert(lines, "    skip-cert-verify: " .. yaml_bool(node.skip_cert_verify))

    if node.servername and node.servername ~= "" then
        table.insert(lines, "    servername: " .. yaml_quote(node.servername))
    end

    if node.client_fingerprint and node.client_fingerprint ~= "" then
        table.insert(lines, "    client-fingerprint: " .. yaml_quote(node.client_fingerprint))
    end

    if node.alpn and node.alpn ~= "" then
        table.insert(lines, "    alpn:")
        for part in tostring(node.alpn):gmatch("[^,]+") do
            part = trim(part)
            if part ~= "" then
                table.insert(lines, "      - " .. yaml_quote(part))
            end
        end
    end

    table.insert(lines, "    network: " .. yaml_quote(node.network or "ws"))

    if node.network == "ws" then
        table.insert(lines, "    ws-opts:")
        table.insert(lines, "      path: " .. yaml_quote(node.ws_path or "/"))
        table.insert(lines, "      headers:")

        local host_val = node.ws_host
        if not host_val or host_val == "" then host_val = node.servername end
        if not host_val or host_val == "" then host_val = node.server end

        table.insert(lines, "        Host: " .. yaml_quote(host_val))
    elseif node.network == "grpc" then
        table.insert(lines, "    grpc-opts:")
        table.insert(lines, "      grpc-service-name: " .. yaml_quote(node.grpc_service_name or ""))
    end

    -- Requested: always UDP true
    table.insert(lines, "    udp: true")
    table.insert(lines, "    tfo: true")
end

local function append_proxies(lines, nodes)
    table.insert(lines, "proxies:")

    for _, node in ipairs(nodes) do
        append_proxy(lines, node)
    end

    table.insert(lines, "")
end

local function append_proxy_groups(lines, nodes, opts)
    opts = opts or {}

    local yaml_type = opts.yaml_type or "fallback"
    local interval = tonumber(opts.interval) or 30
    local timeout = tonumber(opts.timeout) or 3000
    local health_url = trim(opts.health_url or "http://www.gstatic.com/generate_204")
    local lazy = opts.lazy == true
    local lock_index = tonumber(opts.lock_index or 1) or 1

    local names = {}

    for _, node in ipairs(nodes) do
        table.insert(names, node.safe_name)
    end

    if lock_index < 1 then lock_index = 1 end
    if lock_index > #names then lock_index = 1 end

    table.insert(lines, "proxy-groups:")

    if yaml_type == "lock" then
        table.insert(lines, "  - name: MAIN")
        table.insert(lines, "    type: select")
        table.insert(lines, "    proxies:")
        table.insert(lines, "      - " .. yaml_quote(names[lock_index]))
        table.insert(lines, "")

    elseif yaml_type == "global" then
        table.insert(lines, "  - name: GLOBAL")
        table.insert(lines, "    type: select")
        table.insert(lines, "    proxies:")

        for _, name in ipairs(names) do
            table.insert(lines, "      - " .. yaml_quote(name))
        end

        table.insert(lines, "")

        table.insert(lines, "  - name: MAIN")
        table.insert(lines, "    type: select")
        table.insert(lines, "    proxies:")
        table.insert(lines, "      - GLOBAL")
        table.insert(lines, "")

    else
        table.insert(lines, "  - name: MAIN")
        table.insert(lines, "    type: fallback")
        table.insert(lines, "    url: " .. yaml_quote(health_url))
        table.insert(lines, "    interval: " .. tostring(interval))
        table.insert(lines, "    timeout: " .. tostring(timeout))
        table.insert(lines, "    lazy: " .. yaml_bool(lazy))
        table.insert(lines, "    proxies:")

        for _, name in ipairs(names) do
            table.insert(lines, "      - " .. yaml_quote(name))
        end

        table.insert(lines, "")
    end

    table.insert(lines, "  - name: ADS")
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies:")

    if opts.ads_policy == "direct" then
        table.insert(lines, "      - DIRECT")
        table.insert(lines, "      - REJECT")
    else
        table.insert(lines, "      - REJECT")
        table.insert(lines, "      - DIRECT")
    end

    table.insert(lines, "")
end

local function append_rule_providers(lines, block_ads)
    if not block_ads then return end

    table.insert(lines, "rule-providers:")
    table.insert(lines, "  Ads:")
    table.insert(lines, "    type: http")
    table.insert(lines, "    behavior: domain")
    table.insert(lines, "    url: https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml")
    table.insert(lines, "    path: ./rule_provider/anti-ad-clash.yaml")
    table.insert(lines, "    interval: 86400")
    table.insert(lines, "")
end

local function append_rules(lines, opts)
    opts = opts or {}

    local yaml_type = opts.yaml_type or "fallback"
    local block_ads = opts.block_ads == true

    local final_group = "MAIN"
    if yaml_type == "global" then
        final_group = "GLOBAL"
    end

    table.insert(lines, "rules:")

    -- Speedtest / Ookla paksa proxy dahulu
    table.insert(lines, "  - DOMAIN-SUFFIX,speedtest.net," .. final_group)
    table.insert(lines, "  - DOMAIN-SUFFIX,ookla.com," .. final_group)
    table.insert(lines, "  - DOMAIN-SUFFIX,ooklaserver.net," .. final_group)
    table.insert(lines, "  - DOMAIN-KEYWORD,speedtest," .. final_group)
    table.insert(lines, "  - DOMAIN-KEYWORD,ookla," .. final_group)

    if block_ads then
        table.insert(lines, "  - RULE-SET,Ads,ADS")
        table.insert(lines, "  - DOMAIN-KEYWORD,ads,ADS")
        table.insert(lines, "  - DOMAIN-KEYWORD,tracking,ADS")

        -- Analytics jangan terlalu agresif default, sebab app speedtest kadang perlukan endpoint telemetry
        if opts.block_analytics == true then
            table.insert(lines, "  - DOMAIN-KEYWORD,analytics,ADS")
        end
    end

    -- LAN/local sahaja direct
    table.insert(lines, "  - GEOIP,LAN,DIRECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,local,DIRECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,lan,DIRECT")
    table.insert(lines, "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve")

    -- Semua internet public masuk proxy group
    table.insert(lines, "  - MATCH," .. final_group)
end

local function build_yaml(nodes, opts)
    opts = opts or {}

    local lines = {}

    append_base_config(lines, opts)
    append_proxies(lines, nodes)
    append_proxy_groups(lines, nodes, opts)
    append_rule_providers(lines, opts.block_ads == true)
    append_rules(lines, opts)

    return table.concat(lines, "\n") .. "\n"
end

local function ensure_dir(path)
    if not fs.access(path) then
        fs.mkdirr(path)
    end
end

local function unique_filename(dir, base, overwrite)
    ensure_dir(dir)

    base = safe_name_raw(base or "clash_config")
    if base == "" then base = "clash_config" end

    local fname = string.format("%s/%s.yaml", dir, base)

    if overwrite then
        return fname
    end

    if not fs.stat(fname) then
        return fname
    end

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

    if not ok then
        return nil, err
    end

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
            msg = "Paste VLESS/VMESS kosong"
        })
        return
    end

    local nodes, errors = parse_nodes(input)

    if #nodes == 0 then
        http.write_json({
            status = "error",
            msg = "Tiada node valid dijumpai",
            errors = errors
        })
        return
    end

    local opts = {
        yaml_type = http.formvalue("yaml_type") or "fallback",

        block_ads = http.formvalue("block_ads") == "1",
        block_analytics = http.formvalue("block_analytics") == "1",
        ads_policy = http.formvalue("ads_policy") or "reject",

        interval = tonumber(http.formvalue("interval") or "30") or 30,
        timeout = tonumber(http.formvalue("timeout") or "3000") or 3000,
        health_url = http.formvalue("health_url") or "http://www.gstatic.com/generate_204",
        lazy = http.formvalue("lazy") == "1",

        lock_index = tonumber(http.formvalue("lock_index") or "1") or 1,

        unified_delay = http.formvalue("unified_delay") ~= "0",
        tcp_concurrent = http.formvalue("tcp_concurrent") ~= "0",
        global_fingerprint = http.formvalue("global_fingerprint") or "chrome"
    }

    local yaml = build_yaml(nodes, opts)

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
            msg = "YAML kosong"
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
