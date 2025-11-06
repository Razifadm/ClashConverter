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

-- Parser untuk VLESS
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

-- Parser untuk VMESS
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

-- FUNGSI: Memproses input mentah (multi-baris)
local function parse_all_nodes(raw_input)
    local nodes = {}
    if not raw_input or raw_input == "" then return nodes end

    local lines = util.split(raw_input, "\n")
    local unique_names = {}

    for _, line in ipairs(lines) do
        local trimmed_line = line:match("^%s*(.-)%s*$")

        if trimmed_line ~= "" then
            local node = parse_vless(trimmed_line) or parse_vmess(trimmed_line)

            if node then
                -- Pastikan nama node unik dalam format 'safe_raw'
                local temp_pname = safe_name_raw(node.name or node.server or "node")
                local pname = temp_pname
                local j = 1
                while unique_names[pname] do
                    pname = temp_pname .. "_" .. j
                    j = j + 1
                end
                unique_names[pname] = true
                
                -- Guna nama yang di-sanitized sebagai rujukan di dalam YAML
                node.yaml_name = pname
                
                table.insert(nodes, node)
            end
        end
    end
    return nodes
end


-- FUNGSI: Membina keseluruhan YAML untuk MULTIPLE NODES
local function build_full_config_yaml(nodes)
    if not nodes or #nodes == 0 then return nil, "Tiada node untuk dibina" end

    local proxy_names = {}
    local group_name = "Friendly_Teams" 

    -- Bahagian tetap konfigurasi Clash
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
        "  enhanced-mode: redir-host", 
        "  listen: 0.0.0.0:7874",
        "  nameserver:",
        "    - 8.8.8.8",
        "    - 1.0.0.1",
        "    - https://dns.google/dns-query",
        "  fallback:",
        "    - 1.1.1.1",
        "    - 8.8.4.4",
        "    - https://cloudflare-dns.com/dns-query",
        "    - 112.215.203.254",
        "  default-nameserver:",
        "    - 8.8.8.8",
        "    - 1.1.1.1",
        "    - 112.215.203.254",
        "proxies:",
    }

    -- 1. Bina Senarai Proxies
    for _, node in ipairs(nodes) do
        local pname = node.yaml_name -- Nama unik (safe_raw) untuk rujukan
        local display_name = node.name or pname -- Nama asal untuk paparan
        
        table.insert(proxy_names, display_name) -- Simpan nama untuk group

        table.insert(lines, string.format("  - name: %s", display_name)) 
        table.insert(lines, string.format("    server: %s", node.server or ""))
        table.insert(lines, string.format("    port: %d", node.port or 0))
        table.insert(lines, string.format("    type: %s", node.raw_type or "vless"))
        table.insert(lines, string.format("    uuid: %s", node.uuid or ""))
        table.insert(lines, string.format("    alterId: %d", node.alterId or 0))
        table.insert(lines, string.format("    cipher: %s", node.cipher or "auto"))
        table.insert(lines, string.format("    tls: %s", tostring(node.tls)))
        table.insert(lines, string.format("    skip-cert-verify: %s", tostring(node.skip_cert_verify)))
        table.insert(lines, "    servername: " .. (node.servername or ""))
        table.insert(lines, string.format("    network: %s", node.network or "ws"))

        if node.network=="ws" then
            table.insert(lines,"    ws-opts:")
            table.insert(lines,"      path: "..(node.ws_path or "/"))
            table.insert(lines,"      headers:")
            local host_val = node.ws_headers["Host"] or node.servername or node.server
            table.insert(lines,"        Host: "..host_val)
        end
        table.insert(lines,"    udp: "..tostring(node.udp))
    end

    -- 2. Bina Senarai Proxy Groups
    table.insert(lines,"proxy-groups:")

    -- Group Select Utama (Friendly_Teams)
    table.insert(lines,"  - name: "..group_name)
    table.insert(lines,"    type: select")
    table.insert(lines,"    proxies:")
    for _, pname in ipairs(proxy_names) do
        table.insert(lines, "      - "..pname)
    end
    table.insert(lines, "      - BEST-PING")
    table.insert(lines, "      - DIRECT")

    -- Group URL-Test (BEST-PING)
    table.insert(lines,"  - name: BEST-PING")
    table.insert(lines,"    type: url-test")
    table.insert(lines,"    url: http://www.gstatic.com/generate_204")
    table.insert(lines,"    interval: 300")
    table.insert(lines,"    tolerance: 50")
    table.insert(lines,"    proxies:")
    for _, pname in ipairs(proxy_names) do
        table.insert(lines, "      - "..pname)
    end

    -- 3. Bina Rules
    table.insert(lines,"rules:")
    table.insert(lines,"  - MATCH,"..group_name)

    return table.concat(lines,"\n").."\n"
end

-- Controller
function index()
    entry({"admin","services","clash_converter"}, call("action_index"), _("Clash Converter"), 90).dependent = true
    entry({"admin","services","clash_converter","save"}, call("action_save"), nil).leaf = true
    -- 🔥 Handler baru untuk Preview YAML
    entry({"admin","services","clash_converter","preview"}, call("action_preview"), nil).leaf = true
end

-- Render page
function action_index()
    tpl.render("clash_converter/index", {
        openclash_url = get_openclash_url()
    })
end

-- 🔥 Handler baru untuk Preview YAML (Server-side)
function action_preview()
    http.prepare_content("text/plain")
    local raw_input = http.formvalue("raw_input") or ""
    
    local nodes = parse_all_nodes(raw_input)
    local yaml_content, err = build_full_config_yaml(nodes)
    
    if yaml_content then
        http.write(yaml_content)
    else
        http.write("Error: " .. tostring(err) or "Tiada node sah ditemui.")
    end
end

-- Save handler
function action_save()
    http.prepare_content("application/json")
    local raw_input = http.formvalue("raw_input") or ""
    local name_base = http.formvalue("name_base") or "clash_config"
    local overwrite = http.formvalue("overwrite")=="1"

    if raw_input == "" then
        http.write_json({status="error", msg="Input URI kosong"})
        return
    end

    -- 1. Parse semua node dari input
    local nodes = parse_all_nodes(raw_input)

    if #nodes == 0 then
        http.write_json({status="error", msg="Tiada VLESS/VMESS URI yang sah ditemui"})
        return
    end

    -- 2. Bina keseluruhan konfigurasi YAML
    local yaml_content, err = build_full_config_yaml(nodes)

    if not yaml_content then
        http.write_json({status="error", msg=tostring(err) or "Gagal membina YAML"})
        return
    end

    -- 3. Simpan konfigurasi
    local fname, err = save_config(safe_name_raw(name_base), yaml_content, overwrite)
    if not fname then
        http.write_json({status="error", msg=tostring(err)})
        return
    end

    http.write_json({status="ok", path=fname, count=#nodes})
end
