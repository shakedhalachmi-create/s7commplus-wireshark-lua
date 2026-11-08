# S7CommPlus Wireshark dissector (Lua)

A small, dependency-free Wireshark plugin that decodes the frame header of **Siemens S7CommPlus**,
the protocol used by S7-1200 / S7-1500 PLCs, TIA Portal and newer HMIs.

Out of the box, Wireshark decodes only classic **S7comm** (protocol id `0x32`). S7CommPlus
(protocol id `0x72`) is shown as raw `COTP` data. This plugin makes those packets readable and
filterable: version, request/response/notification, function name, sequence number, session id,
and any readable text inside the message.

It is a single Lua file. No compiling, and no binary plugin that has to match your Wireshark version.

```
No.  Protocol     Info
 12  S7COMM-PLUS  S7CommPlus V1 Request CreateObject seq=2 [4 strings]
 13  S7COMM-PLUS  S7CommPlus V1 Response CreateObject seq=2 [3 strings]
 15  S7COMM-PLUS  S7CommPlus V2 Request SetMultiVariables seq=3 [1 strings]
 40  S7COMM-PLUS  S7CommPlus V3 Request GetMultiVariables seq=12
 41  S7COMM-PLUS  S7CommPlus V3 Response GetMultiVariables seq=12
 77  S7COMM-PLUS  S7CommPlus V3 Request SetVariable seq=20
 80  S7COMM-PLUS  S7CommPlus V3 Notification [4 strings]
 95  S7COMM-PLUS  S7CommPlus Keep-alive
```

## Installation

1. In Wireshark go to **Help → About Wireshark → Folders**. The **Personal Lua Plugins** row shows the folder:
   - Windows: `%APPDATA%\Wireshark\plugins`
   - Linux / macOS: `~/.local/lib/wireshark/plugins`
2. Copy `s7commplus.lua` into that folder (create it if it doesn't exist).
3. Restart Wireshark, or use **Analyze → Reload Lua Plugins** (Ctrl+Shift+L).
4. Check that it loaded: **Help → About Wireshark → Plugins** should list `s7commplus.lua`.

tshark loads it the same way. To try it without installing:

```bash
tshark -X lua_script:s7commplus.lua -r capture.pcap -Y s7cp
```

Tested with Wireshark 4.6. It only uses the standard Lua API, so recent 3.x/4.x versions should also work.

## Display filters

| Filter | Shows |
|---|---|
| `s7cp` | all S7CommPlus packets |
| `s7cp.version == 3` | integrity-protected (V3) messages |
| `s7cp.keepalive` | keep-alive packets |
| `s7cp.opcode == 0x31` | requests (`0x32` responses, `0x33` notifications) |
| `s7cp.function_name == "SetVariable"` | one function |
| `s7cp.write` | write-type functions: SetVariable, SetMultiVariables, SetVarSubStreamed, CreateObject, DeleteObject, Invoke |
| `s7cp.seq == 12 && tcp.port == 50000` | a request and its response (same sequence number, same connection) |
| `s7cp.session_id == 0x12345678` | requests of one session |
| `s7cp.string contains "STOP"` | messages whose body contains this text |
| `s7cp.continuation` | continuation parts of large messages |

Tip: right-click a field (for example *Function name*) in the packet details and choose
**Apply as Column**.

### Fields

| Field | Description |
|---|---|
| `s7cp.version` | protocol version: `0x01`, `0x02`, `0x03`, `0xFE` (keep-alive) |
| `s7cp.datalen` | data length from the header |
| `s7cp.digest_len`, `s7cp.digest` | V3 integrity digest (32 bytes) |
| `s7cp.opcode` | `0x31` Request, `0x32` Response, `0x33` Notification |
| `s7cp.function`, `s7cp.function_name` | function code and its name |
| `s7cp.seq` | sequence number (a response carries the number of its request) |
| `s7cp.session_id` | session id (requests) |
| `s7cp.transport_flags` | transport flags byte |
| `s7cp.notification_object` | subscription object id (notifications) |
| `s7cp.body` | message body (not decoded) |
| `s7cp.string` | each readable ASCII string (6+ chars) found in the body |
| `s7cp.trailer` | frame trailer (`72 <version> 00 00`) |
| `s7cp.keepalive`, `s7cp.write`, `s7cp.continuation` | flags for filtering |

## A short primer on S7CommPlus

### Layers

```
TCP port 102
 └─ TPKT  (4 bytes: 03 00 <length>)
     └─ COTP (3 bytes: 02 F0 80 = data)
         └─ S7CommPlus (starts with 0x72)
```

The plugin registers as a heuristic dissector on COTP, so it also works on non-standard ports
and uses Wireshark's COTP reassembly.

### Frame layout

```
72 | version | length(2) | [V3: digest length + 32-byte digest] | opcode | reserved(2) | function(2)
   | reserved(2) | seq(2) | [session id(4), requests only] | transport flags | body ... | 72 <version> 00 00
```

### Objects and attributes

Classic S7comm reads and writes memory addresses ("DB10, byte 4"). S7CommPlus works more like a
tree of **objects**, each with numbered **attributes**: "read attribute X of object Y", "write value V
to attribute X of object Y". Process data in data blocks is addressed symbolically
(symbol CRC + area + member ids), not by byte offset.

### Versions and security

| Version | Meaning |
|---|---|
| V1 / V2 | session setup and key exchange |
| V3 | **integrity protection**: every message carries a 32-byte digest. The content itself is plaintext, so it can be read but not modified without the session key |
| `0xFE` | keep-alive |
| TLS | newer firmware and TIA Portal versions can wrap the session in TLS. Then the content is encrypted and this plugin sees nothing to decode |

### Typical session

| Step | Messages |
|---|---|
| Connect | TCP handshake, COTP connection request/confirm |
| Session | `InitSsl` (TLS offer), `CreateObject` (the session; client and PLC exchange identity strings) |
| Key exchange | `SetMultiVariables` (V2) |
| Work | `Explore` (browse the object tree), `GetMultiVariables` / `GetVarSubStreamed` (read), `SetVariable` / `SetMultiVariables` (write), `CreateObject` (subscriptions), `Invoke` |
| Monitoring | `Notification` messages pushed by the PLC for active subscriptions |
| Idle | keep-alive every few seconds |

### Function codes

| Code | Name | Code | Name |
|---|---|---|---|
| `0x04BB` | Explore | `0x0542` | SetMultiVariables |
| `0x04CA` | CreateObject | `0x054C` | GetMultiVariables |
| `0x04D4` | DeleteObject | `0x0556` | BeginSequence |
| `0x04F2` | SetVariable | `0x0560` | EndSequence |
| `0x04FC` | GetVariable | `0x056B` | Invoke |
| `0x0506` | AddLink | `0x057C` | SetVarSubStreamed |
| `0x051A` | RemoveLink | `0x0586` | GetVarSubStreamed |
| `0x0524` | GetLink | `0x0590` | GetVariablesAddress |
| `0x059A` | Abort | `0x05A9` | Error |
| `0x05B3` | InitSsl | | |

## Limitations

- Only the frame header is decoded. The body (object ids, attributes, addresses, values) is shown as
  raw bytes plus the readable strings found in it.
- Large messages are split into several PDUs. The first one has the full header; the following
  ones are labelled *continuation of a large message*.
- Function names cover the common codes. Unknown codes are shown as hex.
- TLS-protected sessions cannot be decoded.

## Credits

Function code names and the frame layout follow the open-source S7CommPlus Wireshark dissector by
Thomas Wiens (s7commwireshark project).

## License

MIT, see [LICENSE](LICENSE).
