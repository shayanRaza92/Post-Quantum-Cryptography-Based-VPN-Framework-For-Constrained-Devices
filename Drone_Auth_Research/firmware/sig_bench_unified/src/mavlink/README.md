# MAVLink 2 C library (copied subset)

Official generated MAVLink 2 C headers from https://github.com/mavlink/c_library_v2,
commit `95fe9962f1cda6037bddf585e0e71e00fc6257d1` (26 Nov 2026), not modified.

Copied: the top-level headers and the dialect folders `common/`, `standard/` and `minimal/`
(without `common/testsuite.h`, which only the library's own tests use).

Used by `../../e3_link.ino` for the Step 3 link styles **tunnel** and **v2ext**: the signed
authentication message is sent as real MAVLink 2 `TUNNEL` (id 385, 128-byte payload field) or
`V2_EXTENSION` (id 248, 249-byte payload field) packets, built with `mavlink_msg_*_pack()` and
`mavlink_msg_to_send_buffer()`.

Licence: the MAVLink project releases the generated libraries under the MIT licence
(see https://github.com/mavlink/mavlink, section "License").
