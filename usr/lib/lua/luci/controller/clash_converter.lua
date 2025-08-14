-- /usr/lib/lua/luci/controller/clash_converter.lua
module("luci.controller.clash_converter", package.seeall)

local http   = require("luci.http")
local fs     = require("nixio.fs")
local util   = require("luci.util")
local json   = require("luci.jsonc")
local nixio  = require("nixio")
local sys    = require("luci.sys")
local tpl    = require("luci.template")

-- CONFIG
local SAVE_DIR = "/etc/openclash/config"

-- ambil LAN IP secara dinamik
local function get_lan_ip()
    local ip = sys.exec("uci get network.lan.ipaddr 2>/dev/null"):match("%S+")
    if not ip or ip == "" then
        ip = "192.168.1.1" -- fallback default
    end
    return ip
end

local function get_openclash_url()
    return "http://" .. get_lan_ip() .. "/cgi-bin/luci/admin/services/openclash"
end

local OPENCLASH_RELOAD_CMD = "/etc/init.d/openclash restart >/dev/null 2>&1"

-- URL-decode helper
local function url_decode(s)
    if not s then return s end
    s = tostring(s):gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex,16)) end)
    return s
end

-- base64 decode
local function base64_decode(s)
    if not s then return nil end
    s = tostring(s):gsub("%s+", ""):gsub("%-","+"):gsub("_","/")
    local rem = #s % 4
    if rem > 0 then s = s .. string.rep("=", 4 - rem) end
    local ok, res = pcall(function() return util.base64decode(s) end)
    if ok and res then return res end
    local ok2, nb = pcall(function() return nixio.bin and nixio.bin.b64decode and nixio.bin.b64decode(s) end)
    if ok2 and nb then return nb end
    return nil
end

-- sanitize filename
local function safe_name_raw(name)
    if not name or name == "" then return "node" end
    local s = tostring(name):gsub("^%s+",""):gsub("%s+$","")
    s = s:gsub("[^%w%-%._]", "-")
    s = s:gsub("%-+", "-")
    s = s:lower()
    return s
end

-- unique filename
local function unique_filename(base, overwrite)
    if not fs.access(SAVE_DIR) then fs.mkdir(SAVE_DIR) end
    base = base or "clash_config"
    local fname = string.format("%s/%s.yaml", SAVE_DIR, base)
    if overwrite then return fname end
    if not fs.stat(fname) then return fname end
    local i = 1
    while fs.stat(string.format("%s/%s_%d.yaml", SAVE_DIR, base, i)) do
        i = i + 1
    end
    return string.format("%s/%s_%d.yaml", SAVE_DIR, base, i)
end

-- Parse vmess
local function parse_vmess(line)
    local b64 = line:match("^vmess://(.+)")
    if not b64 then return nil end
    local decoded = base64_decode(b64)
    if not decoded then return nil end
    local ok, obj = pcall(function() return json.parse(decoded) end)
    if not ok or not obj then return nil end
    local node = {}
    node.raw_type = "vmess"
    node.name = obj.ps or obj.tag or obj.remarks or obj.add or obj.host or "vmess_node"
    node.server = obj.add or obj.host or ""
    node.port = tonumber(obj.port) or 0
    node.uuid = obj.id or obj.uuid or ""
    node.alterId = tonumber(obj.aid) or tonumber(obj.alterId) or 0
    node.cipher = "auto"
    node.tls = (obj.tls and tostring(obj.tls) ~= "" and tostring(obj.tls) ~= "0")
    node.skip_cert_verify = true
    node.servername = obj.sni or obj.host or ""
    node.network = obj.net or obj.type or "ws"
    node.ws_path = obj.path or obj.wsPath or "/"
    node.ws_headers = {}
    if obj.host and obj.host ~= "" then node.ws_headers["Host"] = obj.host end
    node.udp = true
    return node
end

-- Parse vless
local function parse_vless(line)
    local raw = line:match("^vless://(.+)")
    if not raw then return nil end
    local before_hash, remark = raw:match("^([^#]+)#?(.*)$")
    remark = (remark and remark ~= "") and url_decode(remark) or nil
    local userpart, hostpart = before_hash:match("^([^@]+)@(.+)$")
    local uuid = nil
    local hostportquery = nil
    if userpart and hostpart then
        uuid = userpart
        hostportquery = hostpart
    else
        hostportquery = before_hash
    end
    local hostport, qstr = hostportquery:match("^([^?]+)%??(.*)$")
    local host, port = hostport:match("^(.-):(%d+)$")
    if not host then host = hostport end
    port = tonumber(port) or 0
    local q = {}
    if qstr and qstr ~= "" then
        for k,v in qstr:gmatch("([^&=]+)=([^&=]+)") do
            q[k] = url_decode(v)
        end
    end
    local node = {}
    node.raw_type = "vless"
    node.server = host or ""
    node.port = port
    node.uuid = uuid or q.uuid or ""
    node.name = remark or q.remark or node.server or "vless_node"
    node.alterId = 0
    node.cipher = "auto"
    node.tls = (q.security == "tls") or (q.tls == "1") or (q.tls == "true")
    node.skip_cert_verify = true
    node.servername = q.sni or q.host or ""
    node.network = q.type or q.net or "ws"
    node.ws_path = q.path or q.wsPath or "/"
    node.ws_headers = {}
    if q.host and q.host ~= "" then node.ws_headers["Host"] = q.host end
    node.udp = true
    return node
end

-- Build YAML
local function build_full_config_yaml(node)
    local name = node.name or node.server or "node"
    local server = node.server or ""
    local port = tonumber(node.port) or 0
    local uuid = node.uuid or ""
    local alterId = tonumber(node.alterId) or 0
    local cipher = node.cipher or "auto"
    local tls = (node.tls and true) or false
    local skip_cert = (node.skip_cert_verify and true) or false
    local servername = node.servername or ""
    local network = node.network or "ws"
    local ws_path = node.ws_path or "/"
    local ws_headers = node.ws_headers or {}
    local pname = safe_name_raw(name)
    local group_name = string.upper(pname)
    local lines = {
        "port: 7890",
        "socks-port: 7891",
        "redir-port: 7892",
        "mixed-port: 7893",
        "tproxy-port: 7895",
        "ipv6: false",
        "mode: rule",
        "log-level: silent",
        "allow-lan: true",
        "external-controller: 0.0.0.0:9090",
        "secret: ''",
        "bind-address: '*'",
        "unified-delay: true",
        "profile:",
        "  store-selected: true",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  enhanced-mode: fake-ip",
        "  listen: 127.0.0.1:7874",
        "  nameserver:",
        "    - 1.1.1.1",
        "    - 1.0.0.1",
        "  fallback:",
        "    - https://cloudflare-dns.com/dns-query",
        "    - https://dns.google/dns-query",
        "  default-nameserver:",
        "    - 8.8.8.8",
        "    - 8.8.4.4",
        "proxies:",
        string.format("  - name: %s", pname),
        string.format("    server: %s", server),
        string.format("    port: %d", port),
        string.format("    type: %s", node.raw_type or "vless"),
        string.format("    uuid: %s", uuid),
        string.format("    alterId: %d", alterId),
        string.format("    cipher: %s", cipher),
        string.format("    tls: %s", tostring(tls)),
        string.format("    skip-cert-verify: %s", tostring(skip_cert)),
        "    servername: " .. (servername ~= "" and servername or ""),
        string.format("    network: %s", network)
    }
    if network == "ws" then
        table.insert(lines, "    ws-opts:")
        table.insert(lines, string.format("      path: %s", ws_path))
        table.insert(lines, "      headers:")
        local host_val = ws_headers["Host"] or servername or server
        table.insert(lines, string.format("        Host: %s", host_val))
    end
    table.insert(lines, string.format("    udp: %s", tostring(node.udp and true or false)))
    table.insert(lines, "proxy-groups:")
    table.insert(lines, string.format("  - name: %s", group_name))
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies:")
    table.insert(lines, string.format("      - %s", pname))
    table.insert(lines, "      - DIRECT")
    table.insert(lines, "rules:")
    table.insert(lines, string.format("  - MATCH,%s", group_name))
    return table.concat(lines, "\n") .. "\n"
end

-- save file
local function save_config(name_base, content, overwrite)
    local fname = unique_filename(name_base, overwrite)
    local ok, err = pcall(function() fs.writefile(fname, content) end)
    if not ok then return nil, err end
    return fname
end

function index()
    entry({"admin", "services", "clash_converter"}, call("action_index"), _("Clash Converter"), 90).dependent = true
end

function action_index()
    local saved_preview, errors = {}, {}
    if http.getenv("REQUEST_METHOD") == "POST" then
        local overwrite = http.formvalue("overwrite") == "1"
        local autoreload = http.formvalue("autoreload") == "1"
        -- ambil nama custom dari form
        local custom_name = safe_name_raw(http.formvalue("name_base") or "")
        local pastebox = http.formvalue("pastebox") or ""
        local lines = {}
        for ln in (pastebox.."\n"):gmatch("([^\r\n]+)\r?\n") do
            ln = ln:match("^%s*(.-)%s*$")
            if ln ~= "" then table.insert(lines, ln) end
        end
        for _, ln in ipairs(lines) do
            local node
            if ln:match("^vless://") then
                node = parse_vless(ln)
            elseif ln:match("^vmess://") then
                node = parse_vmess(ln)
            else
                table.insert(errors, "Unsupported link: " .. ln)
            end
            if node then
                local base = custom_name ~= "" and custom_name or safe_name_raw(node.name or node.server or "node")
                local yaml = build_full_config_yaml(node)
                local fname, ferr = save_config(base, yaml, overwrite)
                if not fname then
                    table.insert(errors, "Failed to save " .. base .. ": " .. tostring(ferr))
                else
                    table.insert(saved_preview, { name = base, fname = fname, yaml = yaml })
                end
            end
        end
        if autoreload and #saved_preview > 0 then
            os.execute(OPENCLASH_RELOAD_CMD .. " &")
        end
    end
    tpl.render("clash_converter/index", {
        saved_preview = saved_preview,
        errors = errors,
        openclash_url = get_openclash_url()
    })
end
