-- drone_auth.lua - Wireshark plug-in that names the Step 3 drone authentication messages
-- (UDP port 47000; formats in firmware/sig_bench_unified/link_protocol.h).
--
-- Use:  wireshark -X lua_script:tools/wireshark/drone_auth.lua results/e3/raw/link_<...>/capture.pcapng
-- or copy this file to ~/.local/lib/wireshark/plugins/ and restart Wireshark.
-- Display filter examples:  droneauth.type == 5     droneauth.alg == 3     droneauth.frame_count > 1

local p = Proto("droneauth", "Drone Authentication (Step 3)")

local TYPES = { [1] = "HELLO", [2] = "GETKEY", [3] = "PUBKEY", [4] = "CHALLENGE", [5] = "AUTH",
                [6] = "RESULT", [7] = "STAT", [8] = "DONE" }
local ALGS = { [0] = "Ed25519", [1] = "ECDSA P-256", [2] = "RSA-3072", [3] = "ML-DSA-44",
               [4] = "ML-DSA-65", [5] = "ML-DSA-87" }
local STYLES = { [0] = "udp", [1] = "mav" }

local f = p.fields
f.type = ProtoField.uint8("droneauth.type", "Message type", base.DEC, TYPES)
f.alg = ProtoField.uint8("droneauth.alg", "Algorithm", base.DEC, ALGS)
f.style = ProtoField.uint8("droneauth.style", "Link style", base.DEC, STYLES)
f.seq = ProtoField.uint16("droneauth.seq", "Sequence")
f.dlen = ProtoField.uint16("droneauth.data_len", "Data length")
f.slen = ProtoField.uint16("droneauth.sig_len", "Signature / key length")
f.data = ProtoField.bytes("droneauth.data", "Data")
f.sig = ProtoField.bytes("droneauth.signature", "Signature / public key")
f.frame_idx = ProtoField.uint8("droneauth.frame_index", "Frame index")
f.frame_count = ProtoField.uint8("droneauth.frame_count", "Frame count")
f.frame_len = ProtoField.uint16("droneauth.frame_payload_len", "Frame payload length")
f.frame_payload = ProtoField.bytes("droneauth.frame_payload", "Frame payload (part of the message)")

function p.dissector(buf, pinfo, tree)
  if buf:len() < 10 then return end
  local magic = buf(0, 2):string()
  pinfo.cols.protocol = "DRONE-AUTH"
  local t = tree:add(p, buf(), "Drone Authentication")
  if magic == "DA" and buf:len() >= 12 then
    local mtype, alg = buf(3, 1):uint(), buf(4, 1):uint()
    t:add(f.type, buf(3, 1)); t:add(f.alg, buf(4, 1)); t:add(f.style, buf(5, 1))
    t:add(f.seq, buf(6, 2)); t:add(f.dlen, buf(8, 2)); t:add(f.slen, buf(10, 2))
    local dlen, slen = buf(8, 2):uint(), buf(10, 2):uint()
    if dlen > 0 and buf:len() >= 12 + dlen then t:add(f.data, buf(12, dlen)) end
    if slen > 0 and buf:len() >= 12 + dlen + slen then t:add(f.sig, buf(12 + dlen, slen)) end
    pinfo.cols.info = string.format("%s %s seq=%d data=%d sig=%d", TYPES[mtype] or "?",
      ALGS[alg] or "", buf(6, 2):uint(), dlen, slen)
  elseif magic == "DF" then
    local mtype, alg = buf(2, 1):uint(), buf(3, 1):uint()
    t:add(f.type, buf(2, 1)); t:add(f.alg, buf(3, 1)); t:add(f.seq, buf(4, 2))
    t:add(f.frame_idx, buf(6, 1)); t:add(f.frame_count, buf(7, 1)); t:add(f.frame_len, buf(8, 2))
    if buf:len() > 10 then t:add(f.frame_payload, buf(10)) end
    pinfo.cols.info = string.format("%s %s seq=%d frame %d/%d (%d B)", TYPES[mtype] or "?", ALGS[alg] or "",
      buf(4, 2):uint(), buf(6, 1):uint() + 1, buf(7, 1):uint(), buf(8, 2):uint())
  end
end

DissectorTable.get("udp.port"):add(47000, p)
