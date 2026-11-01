import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "skills/ctrl-probe/scripts")
)
import observe


def frame(op=19, payload=b"\x01", target=5):
    data = b"\x7f\x7f" + struct.pack(">HHH", 8 + len(payload), target, op) + payload
    return data + observe.crc16(data[2:]).to_bytes(2, "big")


def packet(
    payload,
    seq=100,
    src="192.0.2.10",
    dst="198.51.100.1",
    sport=49153,
    dport=49152,
    flags=24,
    fragment=0,
):
    tcp = (
        struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 80, flags, 65535, 0, 0)
        + payload
    )
    ip = (
        struct.pack(
            ">BBHHHBBH4s4s",
            69,
            0,
            20 + len(tcp),
            1,
            fragment,
            64,
            6,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        + tcp
    )
    return b"\x00" * 14 + b"\x08\x00" + ip


def pcap(items):
    data = struct.pack("<IHHIIII", 2712847316, 2, 4, 0, 0, 262144, 113)
    for index, item in enumerate(items):
        data += struct.pack("<IIII", 1000, index * 1000, len(item), len(item)) + item
    return data


TCP_PORT = 49152
PEERS = {"5": "192.0.2.10", "18": "192.0.2.20"}


class ObserveTests(unittest.TestCase):
    def test_crc_and_stream_split_merge_retransmission(self):
        self.assertEqual(observe.crc16(b"123456789"), 28561)
        a, b = (frame(), frame(35, b"\x01" * 224))
        raw = pcap([packet(a[:5]), packet(a[5:] + b, 105), packet(a[:5])])
        result = observe.decode(raw, PEERS, TCP_PORT)
        self.assertEqual([e["opcode"] for e in result["events"]], ["0x13", "0x23"])
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["events"][0]["packetIndices"], [1, 2])
        self.assertEqual(result["events"][1]["fields"]["VOL"], [1] * 32)

    def test_out_of_order_sequence_wrap(self):
        a = frame()
        raw = pcap([packet(a[5:], 2), packet(a[:5], 4294967293)])
        result = observe.decode(raw, PEERS, TCP_PORT)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["frameHex"], a.hex())

    def test_gap_and_partial_are_not_device_failure(self):
        a = frame()
        result = observe.decode(pcap([packet(a[:4]), packet(a, 120)]), PEERS, TCP_PORT)
        self.assertIn("tcp_sequence_gap", [i["kind"] for i in result["issues"]])
        diff = observe.compare(result, PEERS)
        self.assertEqual(diff["directions"]["Rx"]["state"], "no_samples")
        self.assertEqual(diff["causalFirstDivergence"], "unverified")

    def test_conflicting_retransmission_rejects_flow(self):
        a = frame()
        result = observe.decode(
            pcap([packet(a), packet(a[:5] + b"\xff" + a[6:])]), PEERS, TCP_PORT
        )
        self.assertEqual(result["events"], [])
        self.assertEqual(result["issues"][0]["kind"], "conflicting_tcp_overlap")

    def test_crc_invalid_preserves_raw(self):
        a = frame()[:-1] + b"\x00"
        result = observe.decode(pcap([packet(a)]), PEERS, TCP_PORT)
        self.assertEqual(result["events"][0]["checksum"], "invalid")
        self.assertEqual(result["events"][0]["frameHex"], a.hex())
        self.assertIsNone(result["events"][0]["fields"])

    def test_fragment_and_truncation_are_gaps(self):
        result = observe.decode(pcap([packet(frame(), fragment=8192)]), PEERS, TCP_PORT)
        self.assertEqual(result["issues"][0]["kind"], "ip_fragment_not_reassembled")
        result = observe.decode(pcap([packet(frame())])[:-3], PEERS, TCP_PORT)
        self.assertEqual(result["issues"][0]["kind"], "truncated_packet")

    def test_tcp_connection_without_data_is_visible(self):
        result = observe.decode(
            pcap([packet(b"", flags=2), packet(b"", flags=4)]), PEERS, TCP_PORT
        )
        self.assertEqual(result["events"], [])
        self.assertEqual(result["tcpSummary"]["5"]["packets"], 2)
        self.assertEqual(result["tcpSummary"]["5"]["payloadBytes"], 0)
        self.assertEqual([e["flags"] for e in result["tcpEvents"]], [["SYN"], ["RST"]])
        self.assertEqual(result["timestampResolutionNs"], 1000)

    def test_identity_exclusion_and_named_diff(self):
        a = bytes(224)
        b = bytearray(a)
        b[96] = 3
        raw = pcap(
            [packet(frame(35, a, 5)), packet(frame(35, bytes(b), 18), src=PEERS["18"])]
        )
        diff = observe.compare(observe.decode(raw, PEERS, TCP_PORT), PEERS)
        self.assertEqual(
            diff["directions"]["Rx"]["firstCandidate"]["fields"],
            [{"field": "VOL", "index": 0, "channel": 1, "left": 0, "right": 3}],
        )
        self.assertEqual(diff["sameAggregationWindow"], "unverified")
        raw = pcap([packet(frame(target=5)), packet(frame(target=18), src=PEERS["18"])])
        self.assertIsNone(
            observe.compare(observe.decode(raw, PEERS, TCP_PORT), PEERS)["directions"][
                "Rx"
            ]["firstCandidate"]
        )

    def test_empty_capture_and_offline_reproducibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = pcap([])
            (root / "center.pcap").write_bytes(raw)
            observe.save(
                root / "manifest.json",
                {
                    "rawSha256": observe.digest(raw),
                    "peers": PEERS,
                    "tcpPort": TCP_PORT,
                    "captureId": "test",
                    "captureState": "bounded_capture_finished",
                    "captureQuality": {},
                },
            )
            first = observe.analyze(root)
            self.assertEqual(first, observe.analyze(root))
            self.assertEqual(first["diff"]["directions"]["Rx"]["state"], "no_samples")
            (root / "center.pcap").write_bytes(raw + b"changed")
            with self.assertRaises(ValueError):
                observe.analyze(root)


class ConfigurationTests(unittest.TestCase):
    def test_port_selection_controls_decode(self):
        raw = pcap([packet(frame())])
        self.assertEqual(len(observe.decode(raw, PEERS, TCP_PORT)["events"]), 1)
        self.assertEqual(observe.decode(raw, PEERS, TCP_PORT + 1)["events"], [])

    def test_invalid_port_stops_before_connection(self):
        args = SimpleNamespace(tcp_port=0)
        with patch.object(observe.subprocess, "run") as remote:
            with self.assertRaises(ValueError):
                observe.capture(args)
            remote.assert_not_called()


if __name__ == "__main__":
    unittest.main()
