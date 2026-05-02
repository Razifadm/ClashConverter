module("luci.controller.clash_converter", package.seeall)

local http = require("luci.http")
local fs   = require("nixio.fs")
local util = require("luci.util")
local json = require("luci.jsonc")
local sys  = require("luci.sys")
local tpl  = require("luci.template")

local SAVE_DIR_OPENCLASH = "/etc/openclash/config"
local SAVE_DIR_NIKKI     = "/etc/nikki/profiles"

-- Presets
local MIXED_PORT            = 7890
local DEFAULT_HEALTH_URL    = "http://cp.cloudflare.com/generate_204"
local DEFAULT_INTERVAL      = 30
local DEFAULT_TIMEOUT       = 15000
local DEFAULT_LAZY          = false
local DEFAULT_FAILED_TIMES  = 2
local DEFAULT_FINGERPRINT   = "chrome"
local DEFAULT_ADS_POLICY    = "reject"

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
    if ip == "" then
        ip = "192.168.1.1"
    end
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
    s = s:gsub("^%-+", "")
    s = s:gsub("%-+$", "")
    s = s:upper()

    if s == "" then
        s = "NODE"
    end

    return s
end

local function safe_file_name(name)
    name = trim(name)

    if name == "" then
        name = "clash_config"
    end

    local s = name
    s = s:gsub("[\r\n\t]", " ")
    s = s:gsub("^%s+", "")
    s = s:gsub("%s+$", "")
    s = s:gsub("[^%w%-%._%s]", "-")
    s = s:gsub("%s+", "-")
    s = s:gsub("%-+", "-")
    s = s:gsub("^%-+", "")
    s = s:gsub("%-+$", "")
    s = s:lower()

    if s == "" then
        s = "clash_config"
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
        local base = safe_name_raw(node.name or node.server or node.raw_type or "NODE")
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
        return nil, "Not VLESS"
    end

    local before_hash, remark = raw:match("^([^#]+)#?(.*)$")
    remark = remark and url_decode(remark) or ""

    local userpart, hostpart = before_hash:match("^([^@]+)@(.+)$")
    if not userpart or not hostpart then
        return nil, "Invalid VLESS format"
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
        name = remark ~= "" and remark or q.remark or q.name or host or "VLESS",
        server = host or "",
        port = tonumber(port) or 443,
        uuid = userpart or q.uuid or "",
        tls = (security == "tls" or q.tls == "1" or q.tls == "true"),
        skip_cert_verify = true,
        servername = q.sni or q.servername or q.host or "",
        network = network,

        ws_path = q.path or q.wsPath or "/",
        ws_host = q.host or "",

        grpc_service_name = q.serviceName or q["service-name"] or q.grpcServiceName or "",

        flow = q.flow or "",
        encryption = q.encryption or "none",
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
    if not b64 then
        return nil, "Not VMESS"
    end

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

    local node = {
        raw_type = "vmess",
        name = obj.ps or obj.tag or obj.remarks or obj.add or obj.host or "VMESS",
        server = obj.add or obj.host or "",
        port = tonumber(obj.port) or 443,
        uuid = obj.id or obj.uuid or "",
        alterId = tonumber(obj.aid) or tonumber(obj.alterId) or 0,
        cipher = obj.scy or obj.cipher or "auto",
        tls = tls_raw ~= "" and tls_raw ~= "0" and tls_raw ~= "false",
        skip_cert_verify = true,
        servername = obj.sni or obj.host or "",
        network = network,

        ws_path = obj.path or obj.wsPath or "/",
        ws_host = obj.host or "",

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
    table.insert(lines, "mixed-port: " .. tostring(MIXED_PORT))
    table.insert(lines, "allow-lan: true")
    table.insert(lines, "mode: rule")
    table.insert(lines, "log-level: info")
    table.insert(lines, "ipv6: false")
    table.insert(lines, "tcp-concurrent: true")
    table.insert(lines, "unified-delay: true")
    table.insert(lines, "")

    table.insert(lines, "profile:")
    table.insert(lines, "  store-selected: true")
    table.insert(lines, "  store-fake-ip: false")
    table.insert(lines, "")

    -- TUN disabled because clean YAML worked better.
    table.insert(lines, "tun:")
    table.insert(lines, "  enable: false")
    table.insert(lines, "")

    -- Sniffer preset: enabled but light, no override.
    table.insert(lines, "sniffer:")
    table.insert(lines, "  enable: true")
    table.insert(lines, "  override-destination: false")
    table.insert(lines, "  sniff:")
    table.insert(lines, "    TLS:")
    table.insert(lines, "      ports:")
    table.insert(lines, "        - 443")
    table.insert(lines, "        - 8443")
    table.insert(lines, "        - 2053")
    table.insert(lines, "        - 2083")
    table.insert(lines, "        - 2087")
    table.insert(lines, "        - 2096")
    table.insert(lines, "    HTTP:")
    table.insert(lines, "      ports:")
    table.insert(lines, "        - 80")
    table.insert(lines, "        - 8080")
    table.insert(lines, "        - 8880")
    table.insert(lines, "        - 2052")
    table.insert(lines, "        - 2082")
    table.insert(lines, "        - 2086")
    table.insert(lines, "        - 2095")
    table.insert(lines, "        - 25461")
    table.insert(lines, "")

    -- DNS preset: redir-host because fake-ip caused issues earlier.
    table.insert(lines, "dns:")
    table.insert(lines, "  enable: true")
    table.insert(lines, "  listen: 127.0.0.1:7874")
    table.insert(lines, "  ipv6: false")
    table.insert(lines, "  enhanced-mode: redir-host")
    table.insert(lines, "  use-system-hosts: false")
    table.insert(lines, "  use-hosts: true")
    table.insert(lines, "  default-nameserver:")
    table.insert(lines, "    - 1.1.1.1")
    table.insert(lines, "    - 8.8.8.8")
    table.insert(lines, "  nameserver:")
    table.insert(lines, "    - 1.1.1.1")
    table.insert(lines, "    - 1.0.0.1")
    table.insert(lines, "    - 8.8.8.8")
    table.insert(lines, "    - 8.8.4.4")
    table.insert(lines, "  fallback:")
    table.insert(lines, "    - tls://1.1.1.1")
    table.insert(lines, "    - tls://8.8.8.8")
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

    table.insert(lines, "    network: " .. yaml_quote(node.network or "ws"))
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

    table.insert(lines, "    udp: true")
end

local function append_proxies(lines, nodes)
    table.insert(lines, "proxies:")

    for _, node in ipairs(nodes) do
        append_proxy(lines, node)
    end

    table.insert(lines, "")
end

local function append_fallback_group(lines, group_name, ordered_names)
    table.insert(lines, "  - name: " .. yaml_quote(group_name))
    table.insert(lines, "    type: fallback")
    table.insert(lines, "    proxies:")

    for _, name in ipairs(ordered_names) do
        table.insert(lines, "      - " .. yaml_quote(name))
    end

    table.insert(lines, "    url: " .. DEFAULT_HEALTH_URL)
    table.insert(lines, "    interval: " .. tostring(DEFAULT_INTERVAL))
    table.insert(lines, "    timeout: " .. tostring(DEFAULT_TIMEOUT))
    table.insert(lines, "    lazy: " .. yaml_bool(DEFAULT_LAZY))
    table.insert(lines, "    max-failed-times: " .. tostring(DEFAULT_FAILED_TIMES))
    table.insert(lines, "")
end

local function make_ordered_names(names, primary_index)
    local ordered = {}

    table.insert(ordered, names[primary_index])

    for i, name in ipairs(names) do
        if i ~= primary_index then
            table.insert(ordered, name)
        end
    end

    return ordered
end

local function append_proxy_groups(lines, nodes, ads_policy)
    local names = {}

    for _, node in ipairs(nodes) do
        table.insert(names, node.safe_name)
    end

    table.insert(lines, "proxy-groups:")

    -- Manual selector that points to per-node fallback groups.
    table.insert(lines, "  - name: SELECTOR")
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies:")

    for _, name in ipairs(names) do
        table.insert(lines, "      - " .. yaml_quote(name .. "-FALLBACK"))
    end

    table.insert(lines, "")

    -- Every manual selection is actually a fallback group with chosen node as priority.
    for i, name in ipairs(names) do
        append_fallback_group(lines, name .. "-FALLBACK", make_ordered_names(names, i))
    end

    table.insert(lines, "  - name: ADS")
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies:")

    if ads_policy == "direct" then
        table.insert(lines, "      - DIRECT")
        table.insert(lines, "      - REJECT")
    else
        table.insert(lines, "      - REJECT")
        table.insert(lines, "      - DIRECT")
    end

    table.insert(lines, "")
end

local function append_rule_providers(lines)
    table.insert(lines, "rule-providers:")
    table.insert(lines, "  Ads:")
    table.insert(lines, "    type: http")
    table.insert(lines, "    behavior: domain")
    table.insert(lines, "    url: https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml")
    table.insert(lines, "    path: ./rule_provider/anti-ad-clash.yaml")
    table.insert(lines, "    interval: 86400")
    table.insert(lines, "")
end

local function append_rules(lines)
    table.insert(lines, "rules:")
    table.insert(lines, "  - RULE-SET,Ads,ADS")
    table.insert(lines, "  - DOMAIN-KEYWORD,ads,ADS")
    table.insert(lines, "  - DOMAIN-KEYWORD,tracking,ADS")
    table.insert(lines, "")
    table.insert(lines, "  - GEOIP,LAN,DIRECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,local,DIRECT")
    table.insert(lines, "  - DOMAIN-SUFFIX,lan,DIRECT")
    table.insert(lines, "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
    table.insert(lines, "  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve")
    table.insert(lines, "")
    table.insert(lines, "  - MATCH,SELECTOR")
end

local function build_yaml(nodes, opts)
    opts = opts or {}

    local lines = {}

    append_base_config(lines)
    append_proxies(lines, nodes)
    append_proxy_groups(lines, nodes, opts.ads_policy or DEFAULT_ADS_POLICY)
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

    local opts = {
        ads_policy = http.formvalue("ads_policy") or DEFAULT_ADS_POLICY
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
