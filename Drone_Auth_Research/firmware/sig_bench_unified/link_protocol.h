// link_protocol.h - the drone authentication messages of Step 3 (experiment E3).
// The ground station side is tools/gcs_link_test.py; keep both in step.
//
// All messages are UDP datagrams on port LINK_PORT. Numbers are big-endian.
//
// Whole message (link style "udp": sent as ONE datagram; if it is larger than one Wi-Fi packet,
// the IP layer splits it, and Wireshark shows the pieces):
//   0  'D' 'A'        magic
//   2  version        1
//   3  type           see MSG_* below
//   4  algorithm id   0..5 = position in ALGORITHMS[] (Ed25519, ECDSA-P256, RSA-3072, ML-DSA-44/65/87)
//   5  link style     0 = udp, 1 = mav
//   6  sequence (2)
//   8  data length (2)
//  10  signature or key length (2)
//  12  data, then the signature (or the public key)
// An AUTH message is signed over the header (with the signature-length field, bytes 10-11,
// set to 0, because the ECDSA signature length is only known after signing) and the data.
//
// Link style "mav": the whole message above is cut into frames of at most MAV_PAYLOAD bytes
// (the MAVLink 2 payload limit), each sent as its own UDP datagram with this frame header:
//   0  'D' 'F'        magic
//   2  type           type of the whole message
//   3  algorithm id
//   4  sequence (2)   sequence of the whole message
//   6  frame index    0 .. frame count - 1
//   7  frame count
//   8  payload length (2)
//  10  payload (at most MAV_PAYLOAD bytes)
//
// Link styles "tunnel" (2) and "v2ext" (3): the whole message is sent as REAL MAVLink 2 packets,
// built with the official MAVLink C library (src/mavlink, common dialect), one packet per UDP
// datagram. Style 2 uses TUNNEL (id 385, 128-byte payload field, payload_type in the local-
// experiment range), style 3 uses V2_EXTENSION (id 248, 249-byte payload field). Each packet's
// payload field starts with a 5-byte fragment header, then up to MAVLINK_TUNNEL_DATA or
// MAVLINK_V2EXT_DATA bytes of the message:
//   0  sequence (2)   sequence of the whole message
//   2  fragment index
//   3  fragment count
//   4  bytes of the message in this fragment
// Only the AUTH message is sent this way; the other messages stay as above.
#pragma once
#include <stdint.h>

#define LINK_PORT        47000
#define LINK_VERSION     1
#define MAV_PAYLOAD      255     // MAVLink 2: at most 255 payload bytes per message
#define HDR_LEN          12
#define FRAME_HDR_LEN    10
#define MIN_DATA_LEN     56      // challenge (32) + drone id (16) + drone clock (8)
#define MAX_DATA_LEN     8192

enum { STYLE_UDP = 0, STYLE_MAV = 1, STYLE_TUNNEL = 2, STYLE_V2EXT = 3 };
#define MAVLINK_FRAG_HDR      5
#define MAVLINK_TUNNEL_DATA   (128 - MAVLINK_FRAG_HDR)    // TUNNEL.payload is 128 bytes
#define MAVLINK_V2EXT_DATA    (249 - MAVLINK_FRAG_HDR)    // V2_EXTENSION.payload is 249 bytes
#define MAVLINK_LOCAL_TYPE    32769   // TUNNEL payload_type / V2_EXTENSION message_type: >32767 = local experiment
#define MAV_SYSID_DRONE       1
#define MAV_COMPID_DRONE      191     // MAV_COMP_ID_ONBOARD_COMPUTER
#define MAV_SYSID_GCS         255
#define MAV_COMPID_GCS        190     // MAV_COMP_ID_MISSIONPLANNER

enum {
  MSG_HELLO = 1,       // drone -> broadcast, until the ground station answers: "I am here"
  MSG_GETKEY = 2,      // ground station -> drone: make a key for this algorithm, send the public key
  MSG_PUBKEY = 3,      // drone -> ground station: public key (in the signature/key field)
  MSG_CHALLENGE = 4,   // ground station -> drone: 32-byte random challenge + wanted data length/style
  MSG_AUTH = 5,        // drone -> ground station: data (challenge, id, clock, sensor data) + signature
  MSG_RESULT = 6,      // ground station -> drone: accepted or rejected
  MSG_STAT = 7,        // drone -> ground station: timing measured on the drone (not part of the protocol)
  MSG_DONE = 8,        // ground station -> drone: test finished
};
