module("luci.controller.clash_converter", package.seeall)

local http   = require("luci.http")
local fs     = require("nixio.fs")
local util   = require("luci.util")
local json   = require("luci.jsonc")
local sys    = require("luci.sys")
local tpl    = require("luci.template")

local SAVE_DIR = "/etc/openclash/config"

local function get_lan_ip()
    local ip = sys.exec("uci get network.lan.ipaddr 2>/dev/null"):match("%S+")
    return ip ~= "" and ip or "192.168.1.1"
end

local function get_openclash_url()
    return "http://" .. get_lan_ip() .. "/cgi-bin/luci/admin/services/openclash"
end

local function url_decode(s)
    if not s then return s end
    s = tostring(s):gsub("+", " ")
    return s:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex,16)) end)
end

local function base64_decode(s)
    if not s then return nil end
    s = s:gsub("%s+", ""):gsub("%-","+"):gsub("_","/")
    local rem = #s % 4
    if rem > 0 then s = s .. string.rep("=", 4 - rem) end
    local ok, res = pcall(function() return util.base64decode(s) end)
    if ok and res then return res end
    return nil
end

local function safe_name_raw(name)
    if not name or name == "" then return "node" end
    local s = name:gsub("^%s+",""):gsub("%s+$","")
    s = s:gsub("[^%w%-%._]", "-")
    s = s:gsub("%-+", "-"):lower()
    return s
end

local function unique_filename(base, overwrite)
    if not fs.access(SAVE_DIR) then fs.mkdir(SAVE_DIR) end
    local fname = string.format("%s/%s.yaml", SAVE_DIR, base or "clash_config")
    if overwrite then return fname end
    if not fs.stat(fname) then return fname end
    local i = 1
    while fs.stat(string.format("%s/%s_%d.yaml", SAVE_DIR, base, i)) do i=i+1 end
    return string.format("%s/%s_%d.yaml", SAVE_DIR, base, i)
end

local function save_config(name_base, content, overwrite)
    local fname = unique_filename(name_base, overwrite)
    local ok, err = pcall(function() fs.writefile(fname, content) end)
    if not ok then return nil, err end
    return fname
end

-- Untuk live preview, parser VLESS/VMESS dan build YAML sama macam sebelum ini
local function parse_vless(line)
    local raw = line:match("^vless://(.+)")
    if not raw then return nil end
    local before_hash, remark = raw:match("^([^#]+)#?(.*)$")
    remark = remark ~= "" and url_decode(remark) or nil
    local userpart, hostpart = before_hash:match("^([^@]+)@(.+)$")
    local uuid, hostportquery = userpart, hostpart
    if not uuid then hostportquery = before_hash end
    local hostport, qstr = hostportquery:match("^([^?]+)%??(.*)$")
    local host, port = hostport:match("^(.-):(%d+)$")
    if not host then host = hostport end
    port = tonumber(port) or 0
    local q = {}
    if qstr and qstr~="" then
        for k,v in qstr:gmatch("([^&=]+)=([^&=]+)") do q[k]=url_decode(v) end
    end
    return {
        raw_type = "vless",
        server = host or "",
        port = port,
        uuid = uuid or q.uuid or "",
        name = remark or q.remark or host or "vless_node",
        alterId = 0,
        cipher = "auto",
        tls = (q.security=="tls") or (q.tls=="1") or (q.tls=="true"),
        skip_cert_verify = true,
        servername = q.sni or q.host or "",
        network = q.type or q.net or "ws",
        ws_path = q.path or q.wsPath or "/",
        ws_headers = (q.host and q.host~="") and {Host=q.host} or {},
        udp = true
    }
end

local function parse_vmess(line)
    local b64 = line:match("^vmess://(.+)")
    if not b64 then return nil end
    local decoded = base64_decode(b64)
    if not decoded then return nil end
    local ok, obj = pcall(function() return json.parse(decoded) end)
    if not ok or not obj then return nil end
    return {
        raw_type = "vmess",
        name = obj.ps or obj.tag or obj.remarks or obj.add or obj.host or "vmess_node",
        server = obj.add or obj.host or "",
        port = tonumber(obj.port) or 0,
        uuid = obj.id or obj.uuid or "",
        alterId = tonumber(obj.aid) or tonumber(obj.alterId) or 0,
        cipher = "auto",
        tls = obj.tls and tostring(obj.tls)~="" and tostring(obj.tls)~="0",
        skip_cert_verify = true,
        servername = obj.sni or obj.host or "",
        network = obj.net or obj.type or "ws",
        ws_path = obj.path or obj.wsPath or "/",
        ws_headers = (obj.host and obj.host~="") and {Host=obj.host} or {},
        udp = true
    }
end

-- Build YAML
local function build_full_config_yaml(node)
    local pname = safe_name_raw(node.name or node.server or "node")
    local group_name = pname:upper()
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
        string.format("    server: %s", node.server or ""),
        string.format("    port: %d", node.port or 0),
        string.format("    type: %s", node.raw_type or "vless"),
        string.format("    uuid: %s", node.uuid or ""),
        string.format("    alterId: %d", node.alterId or 0),
        string.format("    cipher: %s", node.cipher or "auto"),
        string.format("    tls: %s", tostring(node.tls)),
        string.format("    skip-cert-verify: %s", tostring(node.skip_cert_verify)),
        "    servername: " .. (node.servername or ""),
        string.format("    network: %s", node.network or "ws")
    }
    if node.network=="ws" then
        table.insert(lines,"    ws-opts:")
        table.insert(lines,"      path: "..(node.ws_path or "/"))
        table.insert(lines,"      headers:")
        local host_val = node.ws_headers["Host"] or node.servername or node.server
        table.insert(lines,"        Host: "..host_val)
    end
    table.insert(lines,"    udp: "..tostring(node.udp))
    table.insert(lines,"proxy-groups:")
    table.insert(lines,"  - name: "..group_name)
    table.insert(lines,"    type: select")
    table.insert(lines,"    proxies:")
    table.insert(lines,"      - "..pname)
    table.insert(lines,"      - DIRECT")
    table.insert(lines,"rules:")
    table.insert(lines,"  - MATCH,"..group_name)
    return table.concat(lines,"\n").."\n"
end

-- Controller
function index()
    entry({"admin","services","clash_converter"}, call("action_index"), _("Clash Converter"), 90).dependent = true
    entry({"admin","services","clash_converter","save"}, call("action_save"), nil).leaf = true
end

-- Render page
function action_index()
    tpl.render("clash_converter/index", {
        openclash_url = get_openclash_url()
    })
end

-- Save handler
function action_save()
    http.prepare_content("application/json")
    local yaml_input = http.formvalue("yaml_input") or ""
    local name_base = http.formvalue("name_base") or "clash_config"
    local overwrite = http.formvalue("overwrite")=="1"

    if yaml_input == "" then
        http.write_json({status="error", msg="YAML kosong"})
        return
    end

    local fname, err = save_config(safe_name_raw(name_base), yaml_input, overwrite)
    if not fname then
        http.write_json({status="error", msg=tostring(err)})
        return
    end

    http.write_json({status="ok", path=fname})
end
