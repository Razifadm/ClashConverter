-- /usr/lib/lua/luci/controller/clash_converter.lua
module("luci.controller.clash_converter", package.seeall)

local http = require("luci.http")
local fs   = require("nixio.fs")
local util = require("luci.util")
local json = require("luci.jsonc")
local nixio = require("nixio")

-- CONFIG
local SAVE_DIR = "/etc/openclash/config"
local OPENCLASH_UI = "http://192.168.1.1/cgi-bin/luci/admin/services/openclash"
local OPENCLASH_RELOAD_CMD = "/etc/init.d/openclash restart >/dev/null 2>&1"

-- Small HTML escape
local function html_escape(s)
    if not s then return "" end
    s = tostring(s)
    s = s:gsub("&","&amp;"):gsub("<","&lt;"):gsub(">","&gt;")
    s = s:gsub('"',"&quot;"):gsub("'","&#39;")
    return s
end

-- URL-decode helper
local function url_decode(s)
    if not s then return s end
    s = tostring(s):gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex,16)) end)
    return s
end

-- base64 decode (try util.base64decode then nixio.bin.b64decode)
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

-- sanitize filename base (lowercase, keep alnum, -, _, .)
local function safe_name_raw(name)
    if not name or name == "" then return "node" end
    local s = tostring(name):gsub("^%s+",""):gsub("%s+$","")
    s = s:gsub("[^%w%-%._]", "-")
    s = s:gsub("%-+", "-")
    s = s:lower()
    return s
end

-- unique filename under SAVE_DIR (unless overwrite true)
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

-- Parse vmess (vmess://base64) -> node table
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

-- Parse vless (supports uuid@host:port?query#remark or host:port?query#remark)
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

-- Build full OpenClash YAML string using the exact template provided
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

    local pname = safe_name_raw(name)   -- used as file & proxy name
    local group_name = string.upper(pname)

    local lines = {}
    table.insert(lines, "port: 7890")
    table.insert(lines, "socks-port: 7891")
    table.insert(lines, "redir-port: 7892")
    table.insert(lines, "mixed-port: 7893")
    table.insert(lines, "tproxy-port: 7895")
    table.insert(lines, "ipv6: false")
    table.insert(lines, "mode: rule")
    table.insert(lines, "log-level: silent")
    table.insert(lines, "allow-lan: true")
    table.insert(lines, "external-controller: 0.0.0.0:9090")
    table.insert(lines, "secret: ''")
    table.insert(lines, "bind-address: '*'")
    table.insert(lines, "unified-delay: true")
    table.insert(lines, "profile:")
    table.insert(lines, "  store-selected: true")
    table.insert(lines, "dns:")
    table.insert(lines, "  enable: true")
    table.insert(lines, "  ipv6: false")
    table.insert(lines, "  enhanced-mode: fake-ip")
    table.insert(lines, "  listen: 127.0.0.1:7874")
    table.insert(lines, "  nameserver:")
    table.insert(lines, "    - 1.1.1.1")
    table.insert(lines, "    - 1.0.0.1")
    table.insert(lines, "  fallback:")
    table.insert(lines, "    - https://cloudflare-dns.com/dns-query")
    table.insert(lines, "    - https://dns.google/dns-query")
    table.insert(lines, "  default-nameserver:")
    table.insert(lines, "    - 8.8.8.8")
    table.insert(lines, "    - 8.8.4.4")

    -- proxies block
    table.insert(lines, "proxies:")
    table.insert(lines, string.format("  - name: %s", pname))
    table.insert(lines, string.format("    server: %s", server))
    table.insert(lines, string.format("    port: %d", port))
    table.insert(lines, string.format("    type: %s", node.raw_type or "vless"))
    table.insert(lines, string.format("    uuid: %s", uuid))
    table.insert(lines, string.format("    alterId: %d", alterId))
    table.insert(lines, string.format("    cipher: %s", cipher))
    table.insert(lines, string.format("    tls: %s", tostring(tls)))
    table.insert(lines, string.format("    skip-cert-verify: %s", tostring(skip_cert)))
    if servername ~= "" then
        table.insert(lines, string.format("    servername: %s", servername))
    else
        table.insert(lines, "    servername: ")
    end

    table.insert(lines, string.format("    network: %s", network))
    if network == "ws" then
        table.insert(lines, "    ws-opts:")
        table.insert(lines, string.format("      path: %s", ws_path))
        table.insert(lines, "      headers:")
        local host_val = ""
        if ws_headers and ws_headers["Host"] and ws_headers["Host"] ~= "" then
            host_val = ws_headers["Host"]
        elseif servername and servername ~= "" then
            host_val = servername
        else
            host_val = server
        end
        table.insert(lines, string.format("        Host: %s", host_val))
    end

    table.insert(lines, string.format("    udp: %s", tostring(node.udp and true or false)))

    -- proxy-groups
    table.insert(lines, "proxy-groups:")
    table.insert(lines, string.format("  - name: %s", group_name))
    table.insert(lines, "    type: select")
    table.insert(lines, "    proxies:")
    table.insert(lines, string.format("      - %s", pname))
    table.insert(lines, "      - DIRECT")

    -- rules
    table.insert(lines, "rules:")
    table.insert(lines, string.format("  - MATCH,%s", group_name))

    return table.concat(lines, "\n") .. "\n"
end

-- write file and return filename or nil,err
local function save_config(name_base, content, overwrite)
    local fname = unique_filename(name_base, overwrite)
    local ok, err = pcall(function() fs.writefile(fname, content) end)
    if not ok then return nil, err end
    return fname
end

-- SINGLE LuCI endpoint: show form (GET) and handle convert/save (POST)
function index()
    entry({"admin", "services", "clash_converter"}, call("action_index"), _("Clash Converter By Raducksijaa"), 90).dependent = true
end

function action_index()
    local method = http.getenv("REQUEST_METHOD")
    if method == "POST" then
        -- form values
        local overwrite = http.formvalue("overwrite") == "1"
        local autoreload = http.formvalue("autoreload") == "1"
        local pastebox = http.formvalue("pastebox") or ""

        -- collect lines
        local lines = {}
        for ln in (pastebox.."\n"):gmatch("([^\r\n]+)\r?\n") do
            ln = ln:match("^%s*(.-)%s*$")
            if ln ~= "" then table.insert(lines, ln) end
        end

        if #lines == 0 then
            http.prepare_content("text/html; charset=utf-8")
            http.write("<h3>No links provided. Press back.</h3>")
            return
        end

        -- process each line, build YAMLs and save
        local saved = {}
        local saved_preview = {}  -- store {name, fname, yaml}
        local errors = {}

        for _, ln in ipairs(lines) do
            local node = nil
            if ln:match("^vless://") then
                node = parse_vless(ln)
            elseif ln:match("^vmess://") then
                node = parse_vmess(ln)
            else
                table.insert(errors, "Unsupported link (not vless/vmess): " .. ln)
            end

            if node then
                -- name from fragment or server; then sanitize
                local rawname = node.name or node.server or "node"
                local base = safe_name_raw(rawname)
                local yaml = build_full_config_yaml(node)
                local fname, ferr = save_config(base, yaml, overwrite)
                if not fname then
                    table.insert(errors, "Failed to save " .. base .. ": " .. tostring(ferr))
                else
                    table.insert(saved, fname)
                    table.insert(saved_preview, { name = base, fname = fname, yaml = yaml })
                end
            end
        end

        -- optional reload
        if autoreload and #saved > 0 then
            -- run reload in background (best-effort)
            os.execute(OPENCLASH_RELOAD_CMD .. " &")
        end

        -- Render preview box with YAML(s)
        http.prepare_content("text/html; charset=utf-8")
        http.write([[<style>
            .mini-box { border:1px solid #ccc; padding:12px; background:#f9f9f9; max-height:420px; overflow:auto; font-family:monospace; white-space:pre; }
            .btn { display:inline-block; margin:8px 6px; padding:8px 12px; background:#2d6cdf; color:#fff; text-decoration:none; border-radius:6px; }
            .btn.secondary { background:#777; }
            .meta { font-size:90%; color:#333; margin-bottom:8px; }
        </style>
        <h2>Preview generated YAML</h2>
        <div class="meta">Saved to: </div>]])

        if #saved_preview == 0 then
            http.write("<p><b>No valid configs created.</b></p>")
        else
            for i,rec in ipairs(saved_preview) do
                http.write(string.format("<h3>%d) %s  (<i>%s</i>)</h3>", i, html_escape(rec.name), html_escape(rec.fname)))
                http.write('<div class="mini-box">')
                http.write(html_escape(rec.yaml))
                http.write('</div><br/>')
            end
        end

        if #errors > 0 then
            http.write("<h3>Warnings / Errors</h3><ul>")
            for _,e in ipairs(errors) do
                http.write("<li>" .. html_escape(e) .. "</li>")
            end
            http.write("</ul>")
        end

        -- Buttons: OK (back to form) and Open OpenClash
        http.write(string.format([[
            <div style="margin-top:12px">
                <a class="btn" href="%s">Open OpenClash UI</a>
                <a class="btn secondary" href="%s">OK</a>
            </div>
        ]], html_escape(OPENCLASH_UI), html_escape(http.getenv("SCRIPT_NAME") .. http.getenv("PATH_INFO") or "/admin/services/clash_converter")))

        return
    end

    -- GET: show the paste form (mini box is the textarea)
    http.prepare_content("text/html; charset=utf-8")
    http.write([[
      <style>
        .form-box { max-width:900px; padding:12px; border-radius:6px; border:1px solid #ddd; background:#fff }
        textarea.paste { width:100%; height:220px; font-family:monospace; padding:8px; box-sizing:border-box; }
        .row { margin-top:10px }
        .btn { padding:8px 12px; background:#2d6cdf; color:#fff; text-decoration:none; border-radius:6px; border:none }
      </style>
      <h1>Clash Converter</h1>
      <div class="form-box">
        <form method="POST" enctype="multipart/form-data">
          <label><strong>Paste VLESS / VMESS links (one per line):</strong></label><br>
          <textarea class="paste" name="pastebox" placeholder="Paste vless:// or vmess:// links here, one per line"></textarea>
          <div class="row">
            <label><input type="checkbox" name="overwrite" value="1"> Overwrite existing file if same name</label><br>
            <label><input type="checkbox" name="autoreload" value="1"> Auto reload OpenClash after save</label><br>
          </div>
          <div class="row">
            <button class="btn" type="submit">Convert & Preview</button>
            <a class="btn" style="background:#444;margin-left:10px" href="]] .. html_escape(OPENCLASH_UI) .. [[">Open OpenClash UI</a>
          </div>
        </form>
      </div>
      <p style="color:#666;margin-top:8px">After Convert the YAML(s) will be saved to <code>/etc/openclash/config/</code>. Names are taken from the fragment (#name) or host if fragment missing.</p>
    ]])
end
