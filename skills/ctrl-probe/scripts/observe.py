import argparse
import hashlib
import ipaddress
import json
import re
import shlex
import socket
import struct
import subprocess
import time
import uuid
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def crc16(data):
    value = 0xFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x8408 if value & 1 else 0)
    return value


def packets(raw, issues):
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1000),
        b"\xa1\xb2\xc3\xd4": (">", 1000),
        b"\x4d\x3c\xb2\xa1": ("<", 1),
        b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    if len(raw) < 24 or raw[:4] not in formats:
        raise ValueError("classic pcap required; pcapng is not supported")
    endian, multiplier = formats[raw[:4]]
    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    if linktype not in (1, 101, 113, 276):
        raise ValueError("unsupported pcap link type: " + str(linktype))
    offset, index = 24, 0
    while offset < len(raw):
        index += 1
        if offset + 16 > len(raw):
            issues.append({"kind": "truncated_pcap_header", "packet": index})
            break
        sec, fraction, captured, original = struct.unpack_from(
            endian + "IIII", raw, offset
        )
        offset += 16
        data = raw[offset : offset + captured]
        offset += captured
        if len(data) != captured or captured < original:
            issues.append({"kind": "truncated_packet", "packet": index})
            continue
        yield index, sec * 1000000000 + fraction * multiplier, linktype, data


def tcp_packet(index, timestamp, linktype, data, issues):
    try:
        if linktype == 1:
            ether = struct.unpack_from(">H", data, 12)[0]
            start = 14
            while ether in (0x8100, 0x88A8):
                ether = struct.unpack_from(">H", data, start + 2)[0]
                start += 4
        elif linktype == 113:
            ether = struct.unpack_from(">H", data, 14)[0]
            start = 16
        elif linktype == 276:
            ether = struct.unpack_from(">H", data, 0)[0]
            start = 20
        else:
            ether = 0x0800 if data[0] >> 4 == 4 else 0x86DD
            start = 0
        if ether != 0x0800:
            issues.append({"kind": "non_ipv4_not_decoded", "packet": index})
            return
        ip = data[start:]
        ihl = (ip[0] & 15) * 4
        length = struct.unpack_from(">H", ip, 2)[0]
        if ihl < 20 or len(ip) < length:
            raise ValueError("invalid IP length")
        if struct.unpack_from(">H", ip, 6)[0] & 0x3FFF:
            issues.append({"kind": "ip_fragment_not_reassembled", "packet": index})
            return
        if ip[9] != 6:
            return
        tcp = ip[ihl:length]
        sport, dport, sequence = struct.unpack_from(">HHI", tcp, 0)
        header = (tcp[12] >> 4) * 4
        if header < 20 or len(tcp) < header:
            raise ValueError("invalid TCP length")
        return {
            "packet": index,
            "timestampNs": timestamp,
            "src": socket.inet_ntoa(ip[12:16]),
            "dst": socket.inet_ntoa(ip[16:20]),
            "sport": sport,
            "dport": dport,
            "seq": (sequence + bool(tcp[13] & 2)) & 0xFFFFFFFF,
            "syn": bool(tcp[13] & 2),
            "flags": tcp[13],
            "payload": tcp[header:],
        }
    except (IndexError, struct.error, ValueError) as error:
        issues.append(
            {"kind": "malformed_packet", "packet": index, "detail": str(error)}
        )


def decode_fields(opcode, payload):
    if opcode == 0x23 and len(payload) == 224:
        names = ("status", "NOCC", "OCC", "VOL", "DS", "SFR", "SMT")
        return {
            name: list(payload[i * 32 : (i + 1) * 32]) for i, name in enumerate(names)
        }
    return {"payloadBytes": list(payload)}


def frames_from_segments(segments, identity, issues):
    if not segments:
        return []
    anchor = segments[0]["seq"]

    def relative(seq):
        return ((seq - anchor + 0x80000000) & 0xFFFFFFFF) - 0x80000000

    ordered = sorted(segments, key=lambda s: (relative(s["seq"]), s["packet"]))
    groups, data, spans, base, expected = [], bytearray(), [], None, None
    for segment in ordered:
        sequence = relative(segment["seq"])
        body = segment["payload"]
        if not body:
            continue
        if expected is None or sequence > expected:
            if expected is not None:
                issues.append(
                    dict(
                        identity,
                        kind="tcp_sequence_gap",
                        missingBytes=sequence - expected,
                        packet=segment["packet"],
                    )
                )
                groups.append((bytes(data), spans))
            base, data, spans = sequence, bytearray(), []
            expected = sequence
        overlap = max(0, expected - sequence)
        if overlap:
            available = min(overlap, len(body))
            if data[sequence - base : sequence - base + available] != body[:available]:
                issues.append(
                    dict(
                        identity,
                        kind="conflicting_tcp_overlap",
                        packet=segment["packet"],
                    )
                )
                return []
        tail = body[overlap:]
        if tail:
            begin = len(data)
            data.extend(tail)
            spans.append((begin, len(data), segment["packet"], segment["timestampNs"]))
            expected = sequence + len(body)
    if data:
        groups.append((bytes(data), spans))
    result = []
    for data, spans in groups:
        offset = 0
        while offset < len(data):
            found = data.find(b"\x7f\x7f", offset)
            if found < 0:
                issues.append(
                    dict(identity, kind="unframed_bytes", count=len(data) - offset)
                )
                break
            if found > offset:
                issues.append(
                    dict(identity, kind="unframed_bytes", count=found - offset)
                )
            offset = found
            if len(data) - offset < 4:
                issues.append(dict(identity, kind="partial_frame_tail"))
                break
            size = int.from_bytes(data[offset + 2 : offset + 4], "big") + 2
            if size < 10 or size > 65537:
                issues.append(dict(identity, kind="invalid_frame_length", size=size))
                offset += 1
                continue
            if offset + size > len(data):
                issues.append(
                    dict(
                        identity,
                        kind="partial_frame_tail",
                        expectedBytes=size,
                        presentBytes=len(data) - offset,
                    )
                )
                break
            frame = data[offset : offset + size]
            witnesses = [s for s in spans if s[0] < offset + size and s[1] > offset]
            checksum = crc16(frame[2:-2]) == int.from_bytes(frame[-2:], "big")
            opcode = int.from_bytes(frame[6:8], "big")
            result.append(
                dict(
                    identity,
                    firstPacketNs=min(s[3] for s in witnesses),
                    completePacketNs=max(s[3] for s in witnesses),
                    packetIndices=sorted({s[2] for s in witnesses}),
                    wireIdHex=frame[4:6].hex(),
                    opcode=f"0x{opcode:02X}",
                    frameHex=frame.hex(),
                    payloadHex=frame[8:-2].hex(),
                    checksum="valid" if checksum else "invalid",
                    fields=decode_fields(opcode, frame[8:-2]) if checksum else None,
                )
            )
            if not checksum:
                issues.append(
                    dict(
                        identity,
                        kind="invalid_frame_crc",
                        packetIndices=result[-1]["packetIndices"],
                    )
                )
            offset += size
    return result


def decode(raw, peers, tcp_port):
    issues, streams, sessions, tcp_events = [], {}, {}, []
    tcp_summary = {
        target: {"packets": 0, "payloadBytes": 0, "peerPorts": set()}
        for target in peers
    }
    reverse = {ip: target for target, ip in peers.items()}
    for index, timestamp, linktype, data in packets(raw, issues):
        tcp = tcp_packet(index, timestamp, linktype, data, issues)
        if not tcp:
            continue
        if tcp["sport"] == tcp_port and tcp["dst"] in reverse:
            target, direction, peer_port = reverse[tcp["dst"]], "Tx", tcp["dport"]
        elif tcp["dport"] == tcp_port and tcp["src"] in reverse:
            target, direction, peer_port = reverse[tcp["src"]], "Rx", tcp["sport"]
        else:
            continue
        tcp_summary[target]["packets"] += 1
        tcp_summary[target]["payloadBytes"] += len(tcp["payload"])
        tcp_summary[target]["peerPorts"].add(peer_port)
        if tcp["flags"] & 7:
            tcp_events.append(
                {
                    "target": target,
                    "direction": direction,
                    "packet": index,
                    "timestampNs": timestamp,
                    "peerPort": peer_port,
                    "flags": [
                        name
                        for flag, name in [
                            (2, "SYN"),
                            (16, "ACK"),
                            (1, "FIN"),
                            (4, "RST"),
                        ]
                        if tcp["flags"] & flag
                    ],
                }
            )
        key = (target, direction, peer_port, tcp["src"], tcp["dst"])
        if tcp["syn"] and (key not in sessions or sessions[key][1] != tcp["seq"]):
            sessions[key] = (sessions.get(key, (0, None))[0] + 1, tcp["seq"])
        generation = sessions.get(key, (0, None))[0]
        streams.setdefault(key + (generation,), []).append(tcp)
    events = []
    for key, segments in streams.items():
        target, direction, port, src, dst, generation = key
        events.extend(
            frames_from_segments(
                segments,
                {
                    "target": target,
                    "direction": direction,
                    "connection": f"{src}>{dst}:{port}:g{generation}",
                    "captureStartsMidstream": generation == 0,
                },
                issues,
            )
        )
    events.sort(
        key=lambda e: (
            e["completePacketNs"],
            e["firstPacketNs"],
            e["target"],
            e["direction"],
        )
    )
    for index, event in enumerate(events):
        event["eventId"] = index + 1
    for summary in tcp_summary.values():
        summary["peerPorts"] = sorted(summary["peerPorts"])
    resolution = 1 if raw[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1000
    return {
        "schema": "center_observation.decode.v1",
        "clock": "center.pcap",
        "timestampResolutionNs": resolution,
        "events": events,
        "tcpEvents": tcp_events,
        "tcpSummary": tcp_summary,
        "issues": issues,
    }


def compare(decoded, peers):
    targets = list(peers)
    result = {
        "schema": "center_observation.diff.v1",
        "targets": targets,
        "alignment": "ordinal_within_capture_not_synchronized_trial",
        "sameSettings": "unverified",
        "samePhysicalInput": "unverified",
        "sameAggregationWindow": "unverified",
        "causalFirstDivergence": "unverified",
        "captureIssues": decoded["issues"],
        "tcpSummary": decoded["tcpSummary"],
        "directions": {},
    }
    for direction in ("Tx", "Rx"):
        sequences = [
            [
                e
                for e in decoded["events"]
                if e["target"] == target
                and e["direction"] == direction
                and e["checksum"] == "valid"
            ]
            for target in targets
        ]
        first = None
        for index, (a, b) in enumerate(zip(*sequences)):
            if a["opcode"] != b["opcode"] or a["payloadHex"] != b["payloadHex"]:
                fields = []
                if a["opcode"] == b["opcode"]:
                    for name in a["fields"]:
                        left, right = a["fields"][name], b["fields"].get(name, [])
                        for channel in range(max(len(left), len(right))):
                            av = left[channel] if channel < len(left) else None
                            bv = right[channel] if channel < len(right) else None
                            if av != bv:
                                fields.append(
                                    {
                                        "field": name,
                                        "index": channel,
                                        "channel": channel + 1
                                        if name != "payloadBytes"
                                        else None,
                                        "left": av,
                                        "right": bv,
                                    }
                                )
                first = {
                    "ordinal": index,
                    "leftEvent": a["eventId"],
                    "rightEvent": b["eventId"],
                    "leftOpcode": a["opcode"],
                    "rightOpcode": b["opcode"],
                    "fields": fields,
                    "meaning": "observed candidate; pairing and equal preconditions require verification",
                }
                break
        result["directions"][direction] = {
            "counts": [len(s) for s in sequences],
            "firstCandidate": first,
            "unpairedEvents": [
                [e["eventId"] for e in s[min(map(len, sequences)) :]] for s in sequences
            ],
            "timingNs": [[e["completePacketNs"] for e in s] for s in sequences],
            "state": "no_samples"
            if not all(sequences)
            else "candidate_difference"
            if first
            else "compared_prefix_equal_not_full_equivalence",
        }
    result["byOpcode"] = []
    for direction in ("Tx", "Rx"):
        opcodes = sorted(
            {e["opcode"] for e in decoded["events"] if e["direction"] == direction}
        )
        for opcode in opcodes:
            samples = [
                [
                    e
                    for e in decoded["events"]
                    if e["direction"] == direction
                    and e["target"] == target
                    and e["opcode"] == opcode
                    and e["checksum"] == "valid"
                ]
                for target in targets
            ]
            changes = []
            pair = None
            for a, b in zip(*samples):
                if a["payloadHex"] == b["payloadHex"]:
                    continue
                pair = [a["eventId"], b["eventId"]]
                for name in a["fields"]:
                    left, right = a["fields"][name], b["fields"].get(name, [])
                    for index in range(max(len(left), len(right))):
                        av = left[index] if index < len(left) else None
                        bv = right[index] if index < len(right) else None
                        if av != bv:
                            changes.append(
                                {"field": name, "index": index, "left": av, "right": bv}
                            )
                break
            result["byOpcode"].append(
                {
                    "direction": direction,
                    "opcode": opcode,
                    "counts": [len(s) for s in samples],
                    "firstDifferentPair": pair,
                    "fields": changes,
                    "pairing": "same-opcode ordinal, unverified event equivalence",
                }
            )
    return result


def analyze(directory):
    root = Path(directory)
    manifest = json.loads((root / "manifest.json").read_text())
    raw = (root / "center.pcap").read_bytes()
    if digest(raw) != manifest["rawSha256"]:
        raise ValueError("raw evidence hash mismatch")
    if (
        "sourceEvidenceSha256" in manifest
        and digest((root / "source-anchors.json").read_bytes())
        != manifest["sourceEvidenceSha256"]
    ):
        raise ValueError("source evidence metadata hash mismatch")
    output = decode(raw, manifest["peers"], manifest["tcpPort"])
    output["captureId"] = manifest["captureId"]
    output["rawSha256"] = digest(raw)
    output["decoderSha256"] = digest(Path(__file__).read_bytes())
    difference = compare(output, manifest["peers"])
    difference["captureState"] = manifest["captureState"]
    difference["captureQuality"] = manifest["captureQuality"]
    difference["generationStable"] = manifest.get("generationStable")
    revision = output["decoderSha256"][:16]
    dest = root / "derived" / revision
    dest.mkdir(parents=True, exist_ok=True)
    save(dest / "decode.json", output)
    save(dest / "diff.json", difference)
    for target in manifest["peers"]:
        with (dest / f"{target}.timeline.jsonl").open("w") as f:
            for event in output["events"]:
                if event["target"] == target:
                    f.write(json.dumps(event) + "\n")
    return {
        "derived": str(dest),
        "events": len(output["events"]),
        "issues": len(output["issues"]),
        "diff": difference,
    }


SNAPSHOT = """
import json,subprocess,pathlib,time
def read(args):
 p=subprocess.run(args,capture_output=True,text=True)
 return {'stdout':p.stdout,'stderr':p.stderr,'exitCode':p.returncode}
print(json.dumps({'timeNs':time.time_ns(),'hostname':read(['hostname']), 'user':read(['id','-un']),
 'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'processes':read(['ps','-o','pid,ppid,lstart,args','-C','rcStart','-C','fepStart','-C','mmiMain','-C','cmdMain']),
 'sockets':read(['ss','-nt']), 'clock':read(['timedatectl','show','-p','NTPSynchronized','-p','Timezone'])}))
"""


def ssh_args(alias):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", alias):
        raise ValueError("invalid SSH alias")
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=8",
        alias,
    ]


def capture(args):
    if not 1 <= args.tcp_port <= 65535:
        raise ValueError("TCP port must be 1..65535")
    peers = {}
    for entry in args.peer:
        target, address = entry.split("=", 1)
        if not re.fullmatch(r"[1-9][0-9]*", target):
            raise ValueError("target must be a positive integer")
        if target in peers:
            raise ValueError("duplicate target")
        peers[target] = str(ipaddress.IPv4Address(address))
    if len(peers) != 2 or len(set(peers.values())) != 2:
        raise ValueError("two distinct target=IPv4 bindings required")
    if not 1 <= args.seconds <= 600:
        raise ValueError("capture duration must be 1..600 seconds")
    root = Path(args.out)
    root.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name("source-anchors.json")
    (root / "source-anchors.json").write_bytes(source.read_bytes())

    def snapshot():
        r = subprocess.run(
            ssh_args(args.ssh) + ["python3 -"],
            input=SNAPSHOT,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if r.returncode:
            raise ValueError("snapshot SSH failed: " + r.stderr[:300])
        return json.loads(r.stdout)

    before = snapshot()
    save(root / "before.json", before)
    if (
        before["hostname"]["stdout"].strip() != args.expected_host
        or before["user"]["stdout"].strip() != args.expected_user
    ):
        raise ValueError("identity mismatch; capture not started")
    capture_id = str(uuid.uuid4())
    filter_text = (
        f"tcp port {args.tcp_port} and ("
        + " or ".join("host " + ip for ip in peers.values())
        + ")"
    )
    remote = shlex.join(
        [
            "sudo",
            "-n",
            "timeout",
            "-s",
            "INT",
            str(args.seconds),
            "tcpdump",
            "-n",
            "-i",
            "any",
            "-s",
            "0",
            "-U",
            "-w",
            "-",
            filter_text,
        ]
    )
    manifest = {
        "schema": "center_observation.capture.v1",
        "captureId": capture_id,
        "peers": peers,
        "sshAlias": args.ssh,
        "tcpPort": args.tcp_port,
        "filter": filter_text,
        "requestedSeconds": args.seconds,
        "captureState": "in_progress",
        "captureQuality": {},
        "rawSha256": None,
        "collectorSha256": digest(Path(__file__).read_bytes()),
        "startedLaptopNs": time.time_ns(),
        "sourceEvidence": "source-anchors.json",
        "sourceEvidenceSha256": digest(source.read_bytes()),
        "logicalTargetBinding": "explicit IP bindings; verify current device identity separately",
    }
    save(root / "manifest.json", manifest)
    error, code = None, None
    with (
        (root / "center.pcap").open("wb") as raw,
        (root / "tcpdump.stderr").open("wb") as stderr,
    ):
        child = subprocess.Popen(
            ssh_args(args.ssh) + [remote],
            stdin=subprocess.DEVNULL,
            stdout=raw,
            stderr=stderr,
        )
        try:
            code = child.wait(timeout=args.seconds + 20)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            error = type(exc).__name__
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    manifest["endedLaptopNs"] = time.time_ns()
    manifest["exitCode"] = code
    manifest["error"] = error
    manifest["captureState"] = (
        "bounded_capture_finished"
        if code in (0, 124) and not error
        else "incomplete_remote_cleanup_unverified"
    )
    stats = (root / "tcpdump.stderr").read_text(errors="replace")
    for key, pattern in [
        ("captured", r"(\d+) packets captured"),
        ("receivedByFilter", r"(\d+) packets received by filter"),
        ("kernelDropped", r"(\d+) packets dropped by kernel"),
    ]:
        match = re.search(pattern, stats)
        manifest["captureQuality"][key] = int(match.group(1)) if match else None
    manifest["captureQuality"]["wholeExperimentLoss"] = "unknown"
    manifest["rawSha256"] = digest((root / "center.pcap").read_bytes())
    try:
        after = snapshot()
        save(root / "after.json", after)
        manifest["generationStable"] = (
            before["bootId"] == after["bootId"]
            and before["processes"]["stdout"] == after["processes"]["stdout"]
        )
    except Exception as exc:  # noqa: BLE001
        # Preserve the completed capture if the later snapshot fails unexpectedly.
        manifest["postSnapshotError"] = str(exc)
        manifest["generationStable"] = None
    save(root / "manifest.json", manifest)
    return analyze(root)


def main():
    parser = argparse.ArgumentParser(
        description="Read-only center Tx/Rx observation. No controller commands."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--ssh", required=True)
    c.add_argument("--tcp-port", type=int, required=True)
    c.add_argument("--expected-host", required=True)
    c.add_argument("--expected-user", required=True)
    c.add_argument("--peer", action="append", required=True)
    c.add_argument("--seconds", type=int, default=60)
    c.add_argument("--out", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("directory")
    args = parser.parse_args()
    try:
        result = capture(args) if args.command == "capture" else analyze(args.directory)
        print(json.dumps(result, ensure_ascii=False))
    except Exception as exc:  # noqa: BLE001
        # Keep command failures machine-readable at the CLI boundary.
        print(
            json.dumps({"state": "unavailable", "error": str(exc)}, ensure_ascii=False)
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
