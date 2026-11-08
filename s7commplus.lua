-- s7commplus.lua - Wireshark plugin: minimal S7CommPlus (Siemens S7-1200/1500, TIA Portal) dissector.
--
-- https://github.com/shakedhalachmi-create/s7commplus-wireshark-lua   (MIT License)
--
-- Wireshark only decodes classic S7comm (protocol id 0x32). S7CommPlus (protocol id 0x72) is shown
-- as raw "COTP" data. This plugin decodes the S7CommPlus frame header of every COTP data packet
-- that starts with 0x72:
--
--   version      1 / 2 / 3 (3 = integrity protected: a 32-byte digest follows the header),
--                0xFE = keep-alive
--   opcode       Request / Response / Notification
--   function     CreateObject, Explore, GetMultiVariables, SetVariable, ...
--   sequence     request/response sequence number
--   session id   (requests only)
--   strings      readable ASCII strings found in the body (host names, PLC type, status texts ...)
--
-- The message body (addresses, values, object tree) is NOT decoded; it stays as raw bytes.
-- With V3 the body is plaintext but signed; only the key exchange and the digest are not readable.
-- It is not decoded at all when the connection uses TLS (S7-1500 FW >= 2.9 with secure PG/HMI comm).
--
-- Filters:   s7cp                                   all S7CommPlus packets
--            s7cp.version == 3
--            s7cp.keepalive                         keep-alive packets
--            s7cp.opcode == 0x31                    requests   (0x32 responses, 0x33 notifications)
--            s7cp.function_name == "SetVariable"    one function
--            s7cp.write                             write functions (SetVariable, SetMultiVariables,
--                                                   SetVarSubStreamed, CreateObject, DeleteObject, Invoke)
--            s7cp.seq == 12
--            s7cp.string contains "STOP"            readable text in the body
--
-- Function code names are from the open-source S7CommPlus Wireshark dissector (Thomas Wiens).

local s7cp = Proto("s7cp", "S7CommPlus (minimal)")

local OPCODES = { [0x31] = "Request", [0x32] = "Response", [0x33] = "Notification", [0x02] = "Response2" }

local FUNCTIONS = {
    [0x04BB] = "Explore",           [0x04CA] = "CreateObject",      [0x04D4] = "DeleteObject",
    [0x04F2] = "SetVariable",       [0x04FC] = "GetVariable",       [0x0506] = "AddLink",
    [0x051A] = "RemoveLink",        [0x0524] = "GetLink",           [0x0542] = "SetMultiVariables",
    [0x054C] = "GetMultiVariables", [0x0556] = "BeginSequence",     [0x0560] = "EndSequence",
    [0x056B] = "Invoke",            [0x057C] = "SetVarSubStreamed", [0x0586] = "GetVarSubStreamed",
    [0x0590] = "GetVariablesAddress", [0x059A] = "Abort",           [0x05A9] = "Error",
    [0x05B3] = "InitSsl",
}

local WRITE_FUNCTIONS = {
    [0x04F2] = true, [0x0542] = true, [0x057C] = true, [0x04CA] = true, [0x04D4] = true, [0x056B] = true,
}

local f_version   = ProtoField.uint8("s7cp.version", "Protocol version", base.HEX)
local f_datalen   = ProtoField.uint16("s7cp.datalen", "Data length", base.DEC)
local f_keepalive = ProtoField.none("s7cp.keepalive", "Keep-alive")
local f_digestlen = ProtoField.uint8("s7cp.digest_len", "Integrity digest length", base.DEC)
local f_digest    = ProtoField.bytes("s7cp.digest", "Integrity digest")
local f_opcode    = ProtoField.uint8("s7cp.opcode", "Opcode", base.HEX, OPCODES)
local f_function  = ProtoField.uint16("s7cp.function", "Function", base.HEX, FUNCTIONS)
local f_funcname  = ProtoField.string("s7cp.function_name", "Function name")
local f_write     = ProtoField.none("s7cp.write", "Write function")
local f_seq       = ProtoField.uint16("s7cp.seq", "Sequence number", base.DEC)
local f_session   = ProtoField.uint32("s7cp.session_id", "Session id", base.HEX)
local f_tflags    = ProtoField.uint8("s7cp.transport_flags", "Transport flags", base.HEX)
local f_subscr    = ProtoField.uint32("s7cp.notification_object", "Subscription object id", base.HEX)
local f_body      = ProtoField.bytes("s7cp.body", "Body (not decoded)")
local f_string    = ProtoField.string("s7cp.string", "String")
local f_trailer   = ProtoField.bytes("s7cp.trailer", "Trailer")
local f_continuation = ProtoField.none("s7cp.continuation", "Continuation fragment (no digest / header)")

s7cp.fields = { f_version, f_datalen, f_keepalive, f_digestlen, f_digest, f_opcode, f_function, f_funcname,
                f_write, f_seq, f_session, f_tflags, f_subscr, f_body, f_string, f_trailer, f_continuation }

local MIN_STRING = 6     -- shortest printable run reported as a string
local DIGEST_LEN = 0x20  -- V3 integrity digest is always 32 bytes

-- Add every printable ASCII run (>= MIN_STRING chars) in tvb[offset, offset+len) to the tree.
local function add_strings(tree, tvb, offset, len)
    if len <= 0 then return 0 end
    local raw = tvb:raw(offset, len)
    local found, pos = 0, 1
    while true do
        local s, e = string.find(raw, "[\32-\126]+", pos)
        if not s then break end
        if e - s + 1 >= MIN_STRING then
            tree:add(f_string, tvb(offset + s - 1, e - s + 1))
            found = found + 1
        end
        pos = e + 1
    end
    return found
end

local function dissect(tvb, pinfo, root)
    local total = tvb:len()
    if total < 4 or tvb(0, 1):uint() ~= 0x72 then return 0 end
    local version = tvb(1, 1):uint()
    if not (version == 0x01 or version == 0x02 or version == 0x03 or version == 0x20 or version == 0xFE) then
        return 0
    end

    pinfo.cols.protocol = "S7COMM-PLUS"
    local tree = root:add(s7cp, tvb(), "S7CommPlus, version " .. string.format("0x%02X", version))
    tree:add(f_version, tvb(1, 1))
    tree:add(f_datalen, tvb(2, 2))

    -- the frame ends with a 4-byte trailer: 72 <version> 00 00
    local has_trailer = total >= 8 and tvb(total - 4, 1):uint() == 0x72
    local body_end = has_trailer and (total - 4) or total

    if version == 0xFE then
        tree:add(f_keepalive, tvb(0, 2))
        pinfo.cols.info = "S7CommPlus Keep-alive"
        if body_end > 4 then tree:add(f_body, tvb(4, body_end - 4)) end
        if has_trailer then tree:add(f_trailer, tvb(total - 4, 4)) end
        return total
    end

    local off = 4
    if version == 0x03 and total > 5 then
        if tvb(4, 1):uint() ~= DIGEST_LEN then
            -- large V3 messages are split over several frames; only the first one has the digest
            -- and the opcode/function header, the following ones carry just more body data
            tree:add(f_continuation, tvb(0, 4))
            local info = "S7CommPlus V3 continuation fragment"
            if body_end > 4 then
                local body = tree:add(f_body, tvb(4, body_end - 4))
                local n = add_strings(body, tvb, 4, body_end - 4)
                if n > 0 then info = info .. string.format(" [%d strings]", n) end
            end
            if has_trailer then tree:add(f_trailer, tvb(total - 4, 4)) end
            pinfo.cols.info = info
            return total
        end
        tree:add(f_digestlen, tvb(4, 1))
        if 5 + DIGEST_LEN <= total then tree:add(f_digest, tvb(5, DIGEST_LEN)) end
        off = 5 + DIGEST_LEN
    end

    if off + 1 > body_end then return total end
    local opcode = tvb(off, 1):uint()
    if not OPCODES[opcode] then
        -- next PDU of a large (streamed) message: digest, but no opcode/function header
        tree:add(f_continuation, tvb(0, 4))
        local info = string.format("S7CommPlus V%d continuation of a large message", version)
        local body = tree:add(f_body, tvb(off, body_end - off))
        local n = add_strings(body, tvb, off, body_end - off)
        if n > 0 then info = info .. string.format(" [%d strings]", n) end
        if has_trailer then tree:add(f_trailer, tvb(total - 4, 4)) end
        pinfo.cols.info = info
        return total
    end
    tree:add(f_opcode, tvb(off, 1))
    local info = string.format("S7CommPlus V%d %s", version, OPCODES[opcode] or string.format("op 0x%02X", opcode))

    if opcode == 0x33 then
        -- notification: subscription object id follows the opcode
        if off + 5 <= body_end then tree:add(f_subscr, tvb(off + 1, 4)) end
        off = off + 5
    elseif (opcode == 0x31 or opcode == 0x32 or opcode == 0x02) and off + 9 <= body_end then
        -- opcode(1) reserved(2) function(2) reserved(2) seq(2) [session id(4), request only] transport flags(1)
        local fcode = tvb(off + 3, 2):uint()
        local fname = FUNCTIONS[fcode] or string.format("0x%04X", fcode)
        tree:add(f_function, tvb(off + 3, 2))
        tree:add(f_funcname, tvb(off + 3, 2), fname)
        if WRITE_FUNCTIONS[fcode] then tree:add(f_write, tvb(off + 3, 2)) end
        local seq = tvb(off + 7, 2):uint()
        tree:add(f_seq, tvb(off + 7, 2))
        info = info .. " " .. fname .. " seq=" .. seq
        off = off + 9
        if opcode == 0x31 and off + 4 <= body_end then
            tree:add(f_session, tvb(off, 4))
            off = off + 4
        end
        if off + 1 <= body_end then
            tree:add(f_tflags, tvb(off, 1))
            off = off + 1
        end
    end

    if off < body_end then
        local body = tree:add(f_body, tvb(off, body_end - off))
        local n = add_strings(body, tvb, off, body_end - off)
        if n > 0 then info = info .. string.format(" [%d strings]", n) end
    end
    if has_trailer then tree:add(f_trailer, tvb(total - 4, 4)) end

    pinfo.cols.info = info
    return total
end

function s7cp.dissector(tvb, pinfo, root)
    return dissect(tvb, pinfo, root)
end

-- COTP hands the (reassembled) payload of data TPDUs to its heuristic dissectors
local function heur(tvb, pinfo, root)
    if tvb:len() < 4 or tvb(0, 1):uint() ~= 0x72 then return false end
    return dissect(tvb, pinfo, root) > 0
end

s7cp:register_heuristic("cotp", heur)
