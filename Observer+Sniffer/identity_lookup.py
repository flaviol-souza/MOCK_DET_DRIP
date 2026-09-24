#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - identity_lookup.py
#  STEP 2: retrieve a drone's identity from DNS, given its DET.
#
#  Ports the DNS lookup from the researcher's Android reference
#  (org.securedroneid.android.data.AircraftObject.dnsLookup / parseTXTRecord)
#  to the Python observer: a DET seen on the air is resolved to the registered
#  identity (mfg, serial, model, reg_status, and the public key), and the
#  DET<->key binding verified locally.
#
#  TWO-HOP SCHEME (confirmed against live `dig`, 2026-07-18) - NOT RFC 9886 HIP-RR:
#    Hop 1 (PTR):  dig @141.227.148.117 -x <DET>
#        0.b.c.2...ip6.arpa. 86400 IN PTR snfr2025000123.driplab.example.
#    Hop 2 (TXT):  dig @141.227.148.117 TXT snfr2025000123.driplab.example.
#        ... IN TXT "mfg=...; sn=...; model=...; reg_status=...; pubkey=<base64>"
#
#  TXT FORMAT: key=value pairs split on ';' - matches parseTXTRecord field-for-
#  field (mfg, sn, model, reg_status, pubkey). pubkey = base64 of a 32-byte
#  Ed25519 key (their code rejects length != 32; so do we). 32 B => Suite 5.
#
#  DNSSEC - TWO SIGNALS, KEPT SEPARATE:
#    * dnssec_present  : an RRSIG was in the answer (matches the Android
#                        reference, which set dnssecValid=true on presence alone
#                        - NOT safe by itself; a bogus RRSIG "passes").
#    * dnssec_validated: the RRSIG chain actually verifies up to a PINNED trust
#                        anchor (dnssec_anchors.json), RFC 4035. True/False/None
#                        (None = could not validate: no anchor, no crypto lib, or
#                        no route). This is the real integrity check.
#    Trust anchors are STATIC PINS. RFC 5011 (automated rollover) is out of scope
#    for a run-once CLI - see dnssec_anchors.json. DNSSEC is an integrity signal
#    ON THE DNS ANSWER; it is SEPARATE from and does not replace the local
#    DET<->key binding, which stays the decisive trust check.
#
#  PLUGGABLE RESOLVER: the live query needs a route to 141.227.148.117 (absent on
#  a locked build box). lookup_det() takes an injected Resolver:
#    DnsPythonResolver - real queries via dnspython (your machine)
#    MockResolver      - canned answers, for offline tests
#
#  SOURCES: DET<->key binding RFC 9374 3.5.2 (det.verify_det_binding); reverse
#  ip6.arpa. RFC 3596 2.5; TXT format = researcher's zone; DNS_SERVER default =
#  Constants.DNS_SERVER = "141.227.148.117".
# =============================================================================

import base64
import ipaddress

try:
    import det
    HAVE_DET = True
except Exception:
    HAVE_DET = False

# Default DNS server - traceable to Constants.DNS_SERVER. Override with --dns-server.
DEFAULT_DNS_SERVER = "141.227.148.117"

# TXT keys the researcher's zone publishes (AircraftObject.parseTXTRecord).
TXT_KEYS = ("mfg", "sn", "model", "reg_status", "pubkey")


def det_to_ptr_fqdn(det_bytes):
    """DET -> reverse ip6.arpa. name. Exactly what `dig -x <DET>` queries
    (verified against the live server's QUESTION SECTION).

    NOTE: the Android buildReversedIPv6() reversed the raw 32 hex CHARACTERS and
    appended 'ip6.arpa' with no trailing dot. That coincidentally yields the same
    labels (each hex char is a nibble) but is fragile; we build from the
    canonical 128-bit expansion and include the trailing dot."""
    addr = ipaddress.IPv6Address(bytes(det_bytes))
    nibbles = f"{int(addr):032x}"
    return ".".join(reversed(nibbles)) + ".ip6.arpa."


# ===========================================================================
#  Resolver interface + implementations.
# ===========================================================================
class Resolver:
    """DNS transport.
    query_ptr(name) -> {"target": <fqdn>, "rrsig": <bool>} or None
    query_txt(name) -> {"txt": <str>,     "rrsig": <bool>} or None
    'rrsig' = an RRSIG was PRESENT (not validated)."""
    def query_ptr(self, name):
        raise NotImplementedError

    def query_txt(self, name):
        raise NotImplementedError


DEFAULT_ANCHORS_FILE = "dnssec_anchors.json"


def load_dnssec_anchors(path=DEFAULT_ANCHORS_FILE):
    """Read dnssec_anchors.json -> {zone_text(lowered, trailing dot): DNSKEY rdata}.
    Needs dnspython to parse the DNSKEY text. Returns {} on any problem (missing
    file, no dnspython, malformed) so the DNS path simply degrades to
    presence-only instead of failing."""
    import json
    try:
        import dns.rdata, dns.rdataclass, dns.rdatatype, dns.name
    except Exception:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception:
        return {}
    out = {}
    for a in doc.get("anchors", []):
        try:
            zone = dns.name.from_text(a["zone"]).to_text().lower()
            rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                     a["dnskey"])
            out[zone] = rd
        except Exception:
            continue
    return out


class _ValFail(Exception):
    """hard=True  -> a cryptographic proof failed (report validated=False).
    hard=False -> inconclusive (missing record / infra); report validated=None."""
    def __init__(self, msg, hard):
        super().__init__(msg)
        self.hard = hard


class _DnssecValidator:
    """Validates that an RRset's RRSIG chain verifies up to one of the PINNED
    trust anchors (dnssec_anchors.json), RFC 4035. STATIC PIN — no RFC 5011.

    Scope (phase 1): POSITIVE answers only. Negative answers (NSEC/NSEC3 proof
    of NXDOMAIN, e.g. the rogue) are NOT validated here yet and surface as
    None (inconclusive). Verdict per query:
        True  -> chain verified to a pinned anchor
        False -> a cryptographic check failed (pin absent, DS mismatch, bad sig)
        None  -> could not validate (no anchor for the name, no crypto lib,
                 missing record, or network error) -> caller treats as untrusted
                 but NOT proven-bad.
    All logic lives here so observer.py / identity_resolve.py / hierarchy.json
    stay unchanged (tech steering)."""

    def __init__(self, server, timeout, anchors):
        import dns.resolver, dns.flags
        self._anchors = anchors            # {zone_text: DNSKEY rdata}
        self._keycache = {}
        self.last_reason = None            # why the last validate() returned as it did
        self._r = dns.resolver.Resolver(configure=False)
        self._r.nameservers = [server]
        self._r.lifetime = timeout
        self._r.use_edns(0, dns.flags.DO, 1232)   # DO bit -> RRSIGs returned

    def _fetch(self, name, rdtype_text):
        """(rrset, rrsig_rrset) from the ANSWER section, or (None, None)."""
        import dns.rdatatype
        want = dns.rdatatype.from_text(rdtype_text)
        try:
            ans = self._r.resolve(name, rdtype_text, raise_on_no_answer=False)
        except Exception:
            return None, None
        resp = getattr(ans, "response", None)
        if resp is None:
            return None, None
        rrset = rrsig = None
        for rr in resp.answer:
            if rr.rdtype == want and rr.covers == dns.rdatatype.NONE:
                rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG and rr.covers == want:
                rrsig = rr
        return rrset, rrsig

    @staticmethod
    def _contains_key(dnskey_rrset, pin):
        for k in dnskey_rrset:
            if (k.flags == pin.flags and k.protocol == pin.protocol
                    and k.algorithm == pin.algorithm and k.key == pin.key):
                return True
        return False

    @staticmethod
    def _dnskey_matches_ds(zone, dnskey_rrset, ds_rrset):
        import dns.dnssec
        for key in dnskey_rrset:
            for ds in ds_rrset:
                try:
                    made = dns.dnssec.make_ds(zone, key, ds.digest_type)
                except Exception:
                    continue
                if made == ds:
                    return True
        return False

    def _keyset(self, zone):
        """Trusted DNSKEY RRset for `zone` (dns.name.Name). Recurses to a pinned
        anchor via the DS chain. Memoized. Raises _ValFail / ValidationFailure."""
        if zone in self._keycache:
            return self._keycache[zone]
        import dns.dnssec
        dnskey_rr, dnskey_sig = self._fetch(zone, "DNSKEY")
        if dnskey_rr is None or dnskey_sig is None:
            raise _ValFail(f"no signed DNSKEY at {zone}", hard=False)
        dns.dnssec.validate(dnskey_rr, dnskey_sig, {zone: dnskey_rr})  # self-sig
        pin = self._anchors.get(zone.to_text().lower())
        if pin is not None:
            if not self._contains_key(dnskey_rr, pin):
                raise _ValFail(f"pinned anchor key absent from DNSKEY at {zone}",
                               hard=True)
        else:
            import dns.name
            if zone == dns.name.root:
                raise _ValFail("reached root without a pinned anchor", hard=False)
            # Jump to the parent ZONE APEX, not just the next label: reverse-DNS
            # cuts are multi-label (/28 Apex -> RAA -> HDA), so several ip6.arpa
            # labels between two apexes are empty non-terminals with no DNSKEY.
            parent_apex = self._find_zone(zone.parent())
            if parent_apex is None:
                raise _ValFail(f"no signed parent apex above {zone}", hard=False)
            parent_keys = self._keyset(parent_apex)     # recurse to the real apex
            ds_rr, ds_sig = self._fetch(zone, "DS")
            if ds_rr is None or ds_sig is None:
                raise _ValFail(f"no signed DS for {zone}", hard=False)
            dns.dnssec.validate(ds_rr, ds_sig, {parent_apex: parent_keys})
            if not self._dnskey_matches_ds(zone, dnskey_rr, ds_rr):
                raise _ValFail(f"DNSKEY at {zone} does not match its DS", hard=True)
        self._keycache[zone] = dnskey_rr
        return dnskey_rr

    def _find_zone(self, qname):
        """Closest enclosing signed apex (has a DNSKEY). None if unsigned."""
        n = qname
        for _ in range(64):
            rr, sig = self._fetch(n, "DNSKEY")
            if rr is not None and sig is not None:
                return n
            if n == n.parent():
                return None
            n = n.parent()
        return None

    def validate(self, qname_text, rdtype_text):
        if not self._anchors:
            self.last_reason = "no trust anchors loaded (dnssec_anchors.json)"
            return None
        try:
            import dns.name, dns.dnssec
        except Exception as e:
            self.last_reason = f"dnspython unavailable: {e}"
            return None
        try:
            qname = dns.name.from_text(qname_text)
            zone = self._find_zone(qname)
            if zone is None:
                self.last_reason = f"no signed (DNSKEY) apex found at/above {qname_text}"
                return None                     # unsigned / outside the islands
            keys = self._keyset(zone)
            rr, sig = self._fetch(qname, rdtype_text)
            if rr is None or sig is None:
                self.last_reason = f"{rdtype_text} answer carried no RRSIG"
                return None                     # no RRSIG on the answer -> unproven
            dns.dnssec.validate(rr, sig, {zone: keys})
            self.last_reason = f"validated to pinned anchor via zone {zone.to_text()}"
            return True
        except _ValFail as e:
            self.last_reason = (f"crypto failure: {e}" if e.hard
                                else f"inconclusive: {e}")
            return False if e.hard else None
        except Exception as e:
            # UnsupportedAlgorithm (no cryptography) and infra errors are
            # inconclusive; only explicit signature failures are False.
            try:
                import dns.dnssec
                if isinstance(e, dns.dnssec.UnsupportedAlgorithm):
                    self.last_reason = (f"cannot validate algorithm — is "
                                        f"'cryptography' installed? ({e})")
                    return None
                if isinstance(e, dns.dnssec.ValidationFailure):
                    self.last_reason = f"signature validation failed: {e}"
                    return False
            except Exception:
                pass
            self.last_reason = f"error during validation: {e}"
            return None


class DnsPythonResolver(Resolver):
    """Real DNS via dnspython. Runs on the operator's machine.
    Mirrors SimpleResolver(Constants.DNS_SERVER) + DO bit set (RRSIGs returned
    when the zone is signed). dnspython is an OPTIONAL dependency, imported here
    at construction, so the module still loads (with MockResolver) without it.

    If DNSSEC anchors are configured (dnssec_anchors.json), each answer is also
    chain-validated to a pinned anchor and the result surfaced as 'validated'
    (True/False/None). No anchors / no crypto -> 'validated' is None and behaviour
    is exactly the old presence-only path."""
    def __init__(self, server=DEFAULT_DNS_SERVER, timeout=5.0,
                 anchors=None, anchors_path=DEFAULT_ANCHORS_FILE):
        try:
            import dns.resolver
            import dns.rdatatype
            import dns.exception
            import dns.flags
        except Exception as e:
            raise RuntimeError("DnsPythonResolver needs dnspython: "
                               f"pip install dnspython (import failed: {e})")
        self.server = server
        self.timeout = timeout
        self._r = dns.resolver.Resolver(configure=False)
        self._r.nameservers = [server]
        self._r.lifetime = timeout
        # DO bit -> ask for DNSSEC RRSIGs.
        self._r.use_edns(0, dns.flags.DO, 1232)
        # Optional chain validation against pinned anchors.
        self._validator = None
        try:
            anch = load_dnssec_anchors(anchors_path) if anchors is None else anchors
            if anch:
                self._validator = _DnssecValidator(server, timeout, anch)
        except Exception:
            self._validator = None

    def _validate(self, name, rdtype_text):
        if self._validator is None:
            return None
        try:
            return self._validator.validate(name, rdtype_text)
        except Exception:
            return None

    def _query(self, name, rrtype):
        import dns.resolver, dns.exception, dns.rdatatype
        try:
            ans = self._r.resolve(name, rrtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.resolver.NoAnswer, dns.exception.Timeout):
            return None, False
        if ans.rrset is None:
            return None, False
        rrsig_present = False
        try:
            for rr in ans.response.answer:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    rrsig_present = True
                    break
        except Exception:
            pass
        return ans, rrsig_present

    def _reason(self):
        if self._validator is None:
            return "DNSSEC validator disabled (no anchors/dnspython)"
        return self._validator.last_reason

    def query_ptr(self, name):
        ans, sig = self._query(name, "PTR")
        if ans is None:
            return None
        target = str(ans[0].target) if hasattr(ans[0], "target") else str(ans[0])
        v = self._validate(name, "PTR")
        return {"target": target, "rrsig": sig,
                "validated": v, "dnssec_reason": self._reason()}

    def query_txt(self, name):
        ans, sig = self._query(name, "TXT")
        if ans is None:
            return None
        rd = ans[0]
        try:
            txt = b"".join(rd.strings).decode("utf-8", "replace")
        except Exception:
            txt = str(rd).strip('"')
        v = self._validate(name, "TXT")
        return {"txt": txt, "rrsig": sig,
                "validated": v, "dnssec_reason": self._reason()}


class MockResolver(Resolver):
    """Canned answers for offline testing.
    ptr : { "<reverse name>": ("<fqdn>", <rrsig_bool>) }
    txt : { "<fqdn>":         ("<txt>",  <rrsig_bool>) }
    Missing key -> None (NXDOMAIN / no answer)."""
    def __init__(self, ptr=None, txt=None):
        self.ptr = ptr or {}
        self.txt = txt or {}

    def query_ptr(self, name):
        v = self.ptr.get(name)
        return None if v is None else {"target": v[0], "rrsig": v[1]}

    def query_txt(self, name):
        v = self.txt.get(name)
        return None if v is None else {"txt": v[0], "rrsig": v[1]}


# ===========================================================================
#  TXT parsing - matches AircraftObject.parseTXTRecord field-for-field.
# ===========================================================================
def parse_txt_record(txt):
    """Parse 'mfg=...; sn=...; model=...; reg_status=...; pubkey=<base64>'.
    Returns the five keys (missing -> ""), plus 'pubkey_bytes' (32 raw bytes) or
    None, plus 'pubkey_error'. Unknown keys ignored, like the reference."""
    out = {k: "" for k in TXT_KEYS}
    out["pubkey_bytes"] = None
    out["pubkey_error"] = None

    cleaned = txt.replace('"', "").strip()
    for part in cleaned.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if k in out:
            out[k] = v

    if out["pubkey"]:
        try:
            raw = base64.b64decode(out["pubkey"], validate=True)
        except Exception as e:
            out["pubkey_error"] = f"base64 decode failed: {e}"
        else:
            if len(raw) != 32:
                out["pubkey_error"] = (f"public key is {len(raw)} bytes, "
                                       f"expected 32 (Ed25519 / Suite 5)")
            else:
                out["pubkey_bytes"] = raw
    return out


# ===========================================================================
#  Result object.
# ===========================================================================
class DnsIdentity:
    __slots__ = ("det", "ptr_name", "fqdn", "mfg", "sn", "model", "reg_status",
                 "pubkey", "pubkey_b64", "pubkey_error", "binding_ok",
                 "dnssec_present", "dnssec_validated", "dnssec_detail", "error")

    def __init__(self, det_bytes):
        self.det = bytes(det_bytes)
        self.ptr_name = det_to_ptr_fqdn(det_bytes)
        self.fqdn = None
        self.mfg = self.sn = self.model = self.reg_status = ""
        self.pubkey = None
        self.pubkey_b64 = ""            # the raw base64 string from the TXT record
        self.pubkey_error = None
        self.binding_ok = None          # None = not checked (no key / no det.py)
        self.dnssec_present = False     # an RRSIG was in the answer (not proof)
        self.dnssec_validated = None    # True/False/None - chain verified to a pin
        self.dnssec_detail = None       # human-readable why (per hop)
        self.error = None

    def det_hex(self):
        return self.det.hex().upper()

    def det_v6(self):
        return str(ipaddress.IPv6Address(self.det))

    def pubkey_hex(self):
        return self.pubkey.hex().upper() if self.pubkey else None


# ===========================================================================
#  Entry point - the port of dnsLookup() + parseTXTRecord().
# ===========================================================================
def lookup_det(det_bytes, resolver):
    """Resolve a DET to its DNS identity via PTR -> TXT. Returns a DnsIdentity.
    Normal 'not found' cases are reported in result.error, not raised."""
    det_bytes = bytes(det_bytes)
    if len(det_bytes) != 16:
        raise ValueError("DET must be exactly 16 bytes")

    r = DnsIdentity(det_bytes)

    ptr = resolver.query_ptr(r.ptr_name)          # Hop 1: PTR (dig -x <DET>)
    if ptr is None:
        r.error = f"PTR lookup returned no answer for {r.ptr_name}"
        return r
    r.fqdn = ptr["target"]
    if ptr["rrsig"]:
        r.dnssec_present = True

    txt = resolver.query_txt(r.fqdn)              # Hop 2: TXT on the PTR target
    if txt is None:
        r.error = f"TXT lookup returned no answer for {r.fqdn}"
        return r
    if txt["rrsig"]:
        r.dnssec_present = True

    # End-to-end DNSSEC verdict = BOTH hops. False if any hop failed a crypto
    # check; True only if both chains verified to a pinned anchor; else None
    # (inconclusive - no anchor/crypto/route, or negative answer not yet proved).
    hop_vals = [ptr.get("validated"), txt.get("validated")]
    if any(v is False for v in hop_vals):
        r.dnssec_validated = False
    elif all(v is True for v in hop_vals):
        r.dnssec_validated = True
    else:
        r.dnssec_validated = None
    r.dnssec_detail = (f"PTR: {ptr.get('dnssec_reason')} | "
                       f"TXT: {txt.get('dnssec_reason')}")

    parsed = parse_txt_record(txt["txt"])
    r.mfg, r.sn, r.model, r.reg_status = (
        parsed["mfg"], parsed["sn"], parsed["model"], parsed["reg_status"])
    r.pubkey_b64 = parsed["pubkey"]          # raw base64 string as published
    r.pubkey = parsed["pubkey_bytes"]
    r.pubkey_error = parsed["pubkey_error"]

    # DET<->key binding (RFC 9374 3.5.2) - same check as verifyDETHashLocal.
    if r.pubkey is None or not HAVE_DET:
        r.binding_ok = None
    else:
        r.binding_ok = bool(det.verify_det_binding(det_bytes, r.pubkey))

    return r


def to_ua_entry(r):
    """Build the hierarchy.json 'ua' object for this identity. RAA/HDA are read
    from the DET's own bits (RFC 9374 3.3), never guessed."""
    if HAVE_DET:
        f = det.parse_det(r.det)
        raa, hda = f["raa"], f["hda"]
    else:
        upper = int.from_bytes(r.det[:8], "big")
        raa, hda = (upper >> 22) & 0x3FFF, (upper >> 8) & 0x3FFF
    entry = {"det": r.det_hex(), "raa": raa, "hda": hda}
    if r.pubkey is not None:
        entry["public_key"] = r.pubkey_hex()
    note = f"from DNS {r.fqdn}"
    if r.sn:
        note += f" (sn={r.sn})"
    if r.dnssec_validated is True:
        note += "; dnssec VALIDATED (pinned anchor)"
    elif r.dnssec_validated is False:
        note += "; dnssec FAILED"
    elif r.dnssec_present:
        note += "; dnssec_present (not validated)"
    else:
        note += "; dnssec NOT present"
    entry["_role"] = note
    return entry
