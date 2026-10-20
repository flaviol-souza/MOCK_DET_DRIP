#!/usr/bin/env python3
# =============================================================================
#  MOCK DET DRIP - make_wrapper_vector.py   (bench vector T-901)
#
#  Extracts, from a REAL capture, one DRIP Extended-Transport Wrapper together
#  with the co-located non-Auth Message Pack it authenticates, and writes a
#  versioned, self-verifying fixture (JSON). This is the T-901 vector that fixes
#  the byte-exactness test for the app's Wrapper-signature verification
#  (ADR 0003 / RFC 9575 §4.1, §4.3.2, §4.3.3).
#
#  WHY FROM A CAPTURE: the vector must be "as faithful as what the ESP
#  transmits" and must CONFIRM conformance, not define it. So it is pulled from
#  real air bytes and the fixture only ships a Wrapper whose signature actually
#  VERIFIES against the UA's registered key (a "closing" Wrapper).
#
#  The reconstruction reuses the observer's OWN reference logic
#  (odid.reconstruct_wrapper_evidence, byte-identical to the firmware's
#  drip_auth.cpp collect_evidence_order), so the fixture is anchored to the
#  same rule the transmitter uses.
#
#  What the app test needs, and what this fixture provides:
#    evidence_inputs : the co-located non-Auth 25-byte frames (the input to
#                      rebuildWrapperEvidence)
#    evidence        : the reconstructed Evidence bytes (ASTM Message Type order)
#    wrapper_wire    : VNB | VNA | DET | Signature (Evidence cleared on the wire)
#    signed_data     : VNB | VNA | Evidence | DET   (the bytes the UA signed)
#    verification    : proof the signature closes with the UA public key
#    negative_check  : one tampered evidence frame -> signature MUST fail
#
#  Usage:
#     python make_wrapper_vector.py <capture.txt> [-o T901_extended_wrapper.json]
#                                   [--anchor hierarchy.json] [--det <DET>]
# =============================================================================
import argparse
import json
import sys

import odid
import observer

try:
    import ed25519_backend
    HAVE_ED = True
except Exception:
    HAVE_ED = False


def _hex(b):
    return bytes(b).hex().upper()


def _det_v6(det16):
    import ipaddress
    return str(ipaddress.IPv6Address(bytes(det16)))


def find_wrappers(text, keys):
    """Yield (where, pack_bytes, decoded, auth) for every Extended Wrapper in a
    capture, reusing the observer's exact decode pipeline."""
    _fmt, report, _findings = observer.run(text, keys=keys)
    for where, d in report:
        if "_pack_raw" not in d:
            continue
        pack_bytes = d["_pack_raw"]
        pack = odid.split_pack(pack_bytes)
        decoded = [odid.decode_message(m) for m in pack.get("messages_raw", [])]
        for auth in odid.reassemble_auth(decoded):
            if auth.get("sam_type") == 0x02:            # DRIP Wrapper only
                yield where, pack_bytes, decoded, auth


def build_vector(text, keys, source_name, want_det=None):
    """Return the fixture dict for the first Extended Wrapper whose signature
    VERIFIES (a closing Wrapper). Skips non-verifying ones so the vector is
    canonical. Returns None if none found."""
    if not HAVE_ED:
        sys.exit("ed25519_backend unavailable: cannot verify a closing Wrapper.")

    considered = 0
    for where, pack_bytes, decoded, auth in find_wrappers(text, keys):
        sam = auth.get("sam_data", b"")
        if len(sam) < 88:
            continue
        considered += 1
        vnb, vna, det, sig = sam[0:4], sam[4:8], sam[8:24], sam[24:88]
        if want_det and _hex(det) != want_det.upper().replace(":", ""):
            continue

        evidence = odid.reconstruct_wrapper_evidence(decoded)
        signed = bytes(vnb) + bytes(vna) + evidence + bytes(det)

        pub = keys.for_det(bytes(det))
        if pub is None:
            continue                                    # no key on file -> skip
        if not ed25519_backend.verify(pub, signed, sig):
            continue                                    # not a closing Wrapper

        # Co-located non-Auth frames, in pack order and in Evidence (type) order.
        non_auth = [d for d in decoded if d.get("type") != 0x2]
        ordered = sorted(non_auth, key=lambda d: d.get("type", 0xFF))  # stable
        pack_index = {id(d): i for i, d in enumerate(decoded)}

        def frame_entry(d):
            return {
                "pack_index": pack_index[id(d)],
                "type": d.get("type"),
                "type_name": d.get("type_name"),
                "raw": _hex(d["raw"]),                   # 25-byte ASTM message
            }

        # Negative control: flip one byte of the first evidence frame -> the
        # signature MUST NOT verify (proves the vector catches tampering, TL-204).
        neg = bytearray(evidence)
        neg[-1] ^= 0x01
        neg_signed = bytes(vnb) + bytes(vna) + bytes(neg) + bytes(det)
        neg_ok = ed25519_backend.verify(pub, neg_signed, sig)

        return {
            "vector": "T-901",
            "title": "DRIP Extended-Transport Wrapper with co-located Message Pack",
            "purpose": "Byte-exact fixture for Wrapper signature verification "
                       "(rebuildWrapperEvidence). ADR 0003; RFC 9575 §4.1/§4.3.2/§4.3.3.",
            "source": {
                "capture": source_name,
                "location": where,
                "generated_by": "make_wrapper_vector.py (from real air capture)",
                "reconstruction_ref": "odid.reconstruct_wrapper_evidence == "
                                      "firmware drip_auth.cpp collect_evidence_order",
            },
            "identity": {
                "det": _det_v6(det),
                "det_hex": _hex(det),
                "ua_public_key": _hex(pub),
            },
            "message_pack": {
                "raw": _hex(pack_bytes),
                "message_count": len(decoded),
                "note": "ASTM Message Pack (Type 0xF). Header 3 B + N x 25 B.",
            },
            "wrapper_wire": {
                "sam_type": "0x02 (DRIP Wrapper)",
                "note": "Evidence is CLEARED on the wire (§4.3.2). sam_data after "
                        "the 1-byte SAM Type = VNB|VNA|DET|Sig = 88 B.",
                "vnb_le": _hex(vnb),
                "vna_le": _hex(vna),
                "vnb": int.from_bytes(vnb, "little"),
                "vna": int.from_bytes(vna, "little"),
                "det_hex": _hex(det),
                "signature": _hex(sig),
                "sam_data": _hex(sam[:88]),
            },
            "evidence_inputs": {
                "note": "Co-located non-Auth messages (25 B each). Feed these to "
                        "rebuildWrapperEvidence; sort ascending by ASTM Message "
                        "Type (stable), exclude Auth (§4.3.2), max 4 (§4.3.3).",
                "count": len(ordered),
                "in_pack_order": [frame_entry(d) for d in non_auth],
                "in_evidence_order": [frame_entry(d) for d in ordered],
            },
            "evidence": {
                "note": "Reconstructed Evidence = the non-Auth frames concatenated "
                        "in ASTM Message Type order.",
                "hex": _hex(evidence),
                "length": len(evidence),
            },
            "signed_data": {
                "note": "The exact bytes the UA signed (§4.1 Fig 4): "
                        "VNB(4 LE) | VNA(4 LE) | Evidence | UA_DET(16).",
                "hex": _hex(signed),
                "length": len(signed),
            },
            "verification": {
                "backend": ed25519_backend.backend_name(),
                "algorithm": "Ed25519 (RFC 8032)",
                "verified": True,
            },
            "negative_check": {
                "note": "Same Wrapper, but the LAST byte of the Evidence is flipped "
                        "(one tampered co-located frame). Verification MUST be false.",
                "tampered_evidence_hex": _hex(neg),
                "verified": bool(neg_ok),
            },
        }, considered

    return None, considered


def main():
    ap = argparse.ArgumentParser(description="Extract the T-901 Extended-Wrapper "
                                             "bench vector from a real capture.")
    ap.add_argument("capture", help="capture file (Wi-Fi 'Format A' or BLE 'Format BT')")
    ap.add_argument("-o", "--output", default="T901_extended_wrapper.json",
                    help="output fixture path (default: T901_extended_wrapper.json)")
    ap.add_argument("--anchor", default="hierarchy.json",
                    help="trusted-identities file for the UA public keys")
    ap.add_argument("--det", default=None,
                    help="only accept a Wrapper carrying this DET (hex or colonful)")
    args = ap.parse_args()

    try:
        with open(args.capture, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        sys.exit(f"cannot read capture: {e}")

    keys = observer.default_keyring(args.anchor)

    vector, considered = build_vector(text, keys, args.capture, want_det=args.det)
    if vector is None:
        sys.exit(f"No closing Extended Wrapper found "
                 f"({considered} Wrapper(s) seen). Need a capture with a Wrapper "
                 f"whose UA key is in {args.anchor}.")

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(vector, fh, indent=2)
        fh.write("\n")

    v = vector
    ev_types = ", ".join("{}(0x{:X})".format(e["type_name"], e["type"])
                         for e in v["evidence_inputs"]["in_evidence_order"])
    print(f"T-901 vector written: {args.output}")
    print(f"  source        : {v['source']['capture']}  ({v['source']['location']})")
    print(f"  DET           : {v['identity']['det']}")
    print(f"  evidence msgs : {v['evidence_inputs']['count']}  ({ev_types})")
    print(f"  evidence len  : {v['evidence']['length']} B   signed len: {v['signed_data']['length']} B")
    print(f"  signature     : VERIFIED ({v['verification']['backend']})")
    print(f"  negative check: tampered -> verified={v['negative_check']['verified']} (must be False)")


if __name__ == "__main__":
    main()
