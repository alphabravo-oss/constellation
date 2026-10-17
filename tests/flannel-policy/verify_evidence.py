#!/usr/bin/env python3
"""Join actual pod/CRI identity and independently verify packet/server evidence."""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import re
import sys
import unittest
import tempfile
import copy
import uuid


def read_json(path):
    return json.loads(Path(path).read_text())


def native_mac(value):
    # Go encodes net.HardwareAddr ([]byte) as base64; endpoint identity uses
    # HardwareAddr.String(). Compare the same six bytes, never a display guess.
    if not isinstance(value, str):
        raise ValueError("native MAC must be a base64 string")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 6 or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("native MAC must encode exactly six bytes")
    return raw.hex(":")


def build_identity(directory, arguments):
    directory = Path(directory)
    pods = read_json(directory / "pods.json")["items"]
    if {pod["metadata"]["name"] for pod in pods} != {"server-a", "server-b", "client"} or len(pods) != 3:
        raise ValueError("unexpected isolated pod cohort")
    identity = dict(cluster_name=arguments.cluster, namespace=arguments.namespace,
                    node_container=arguments.node, node_pidns=arguments.node_pidns,
                    node_netns=arguments.node_netns, host_pidns=arguments.host_pidns,
                    host_netns=arguments.host_netns, runtime_image=arguments.runtime_image,
                    cni="flannel", pods=[])
    cni = read_json(directory / "flannel.json")
    if not any(plugin.get("type") == "flannel" for plugin in cni.get("plugins", [])):
        raise ValueError("new node is not using Flannel")
    for pod in sorted(pods, key=lambda value: value["metadata"]["name"]):
        metadata, status = pod["metadata"], pod["status"]
        name = metadata["name"]
        cri = read_json(directory / f"cri-{name}.json")
        labels = cri["status"]["labels"]
        container = status["containerStatuses"][0]["containerID"].removeprefix("containerd://")
        expected = {"io.kubernetes.pod.name": name, "io.kubernetes.pod.namespace": arguments.namespace,
                    "io.kubernetes.pod.uid": metadata["uid"]}
        if metadata["namespace"] != arguments.namespace or any(labels.get(key) != value for key, value in expected.items()):
            raise ValueError("CRI and Kubernetes pod ownership disagree")
        if cri["status"]["id"] != container or not re.fullmatch(r"[0-9a-f]{64}", container):
            raise ValueError("container identity differs from exact pod")
        pid = int(cri["info"]["pid"])
        if not 1 < pid <= 2147483647 or ipaddress.ip_address(status["podIP"]) not in ipaddress.ip_network("10.233.0.0/16"):
            raise ValueError("invalid node-local PID or pod address")
        uuid.UUID(metadata["uid"])
        identity["pods"].append(dict(name=name, namespace=arguments.namespace, uid=metadata["uid"],
                                     container_id=container, pid=pid, ip=status["podIP"],
                                     netns=(directory / f"netns-{name}.txt").read_text().strip()))
    return identity


def server_observations(directory):
    rows = {}
    for name in ("server-a", "server-b"):
        for line in (Path(directory) / f"{name}.log").read_text().splitlines():
            item = json.loads(line)
            if item.get("pod") != name or item.get("nonce") in rows:
                raise ValueError("invalid or duplicate actual server observation")
            rows[item["nonce"]] = item
    return rows


def expected_probe(phase, pod, port):
    if phase in ("baseline", "dp-stopped-bypass"):
        return True, 2, 0, 0
    allowed_port = 18081 if pod == "server-b" or phase == "change-a" else 18080
    if port == allowed_port:
        return True, 2, 11 if pod == "server-a" else 22, 1001
    enforced = phase in ("protect-b", "change-a") or phase == "protect-a" and pod == "server-a"
    return not enforced, 7 if enforced else 6, 0, 0


def verify(directory):
    directory = Path(directory)
    evidence = read_json(directory / "driver-evidence" / "packet-evidence.json")
    if evidence.get("passed") is not True:
        raise ValueError("driver did not complete native packet acceptance")
    observations = server_observations(directory)
    client = next(pod for pod in evidence["identity"]["pods"] if pod["name"] == "client")
    expected_phases = {"baseline", "monitor", "protect-a", "protect-b", "change-a", "dp-stopped-bypass"}
    probes = evidence["probes"]
    if len(probes) != 24 or {probe["phase"] for probe in probes} != expected_phases:
        raise ValueError("incomplete policy lifecycle proof")
    pods = {pod["name"]: pod for pod in evidence["identity"]["pods"]}
    endpoints = {endpoint["PodUID"]: endpoint for endpoint in evidence["endpoints"]}
    if len(endpoints) != 2:
        raise ValueError("missing exact discovered endpoint evidence")
    expected_pairs = {(pod, port) for pod in ("server-a", "server-b") for port in (18080, 18081)}
    for phase in expected_phases:
        cohort = [probe for probe in probes if probe["phase"] == phase]
        if len(cohort) != 4 or {(probe["pod"], probe["port"]) for probe in cohort} != expected_pairs:
            raise ValueError("phase omitted or repeated a workload/port")
    nonces = set()
    for probe in probes:
        expected = expected_probe(probe["phase"], probe["pod"], probe["port"])
        if (probe["allowed"], probe["action"], probe["policy_id"], probe.get("application", 0)) != expected:
            raise ValueError("declared outcome does not prove the required policy phase")
        if probe["require_native"] != (probe["phase"] not in ("baseline", "dp-stopped-bypass")):
            raise ValueError("native proof bypassed for an active policy phase")
        nonce = probe["nonce"]
        if nonce in nonces:
            raise ValueError("probe identity reused")
        nonces.add(nonce)
        row = observations.get(nonce)
        if probe["allowed"]:
            if row is None or row["pod"] != probe["pod"] or row["port"] != probe["port"] or row["remote"] != f'{client["ip"]}:{probe["source_port"]}':
                raise ValueError("reachable probe missing exact real server observation")
        elif row is not None:
            raise ValueError("denied nonce reached server")
        if probe["require_native"]:
            if not probe["native"] or probe["queue_packets_after"] <= probe["queue_packets_before"]:
                raise ValueError("missing native verdict or kernel queue traversal")
            pod = pods[probe["pod"]]
            endpoint = endpoints[pod["uid"]]
            if endpoint["Namespace"] != pod["namespace"] or endpoint["PodName"] != pod["name"] or pod["ip"] not in endpoint["IPs"]:
                raise ValueError("native endpoint ownership mismatch")
            for event in probe["native"]:
                if native_mac(event["EPMAC"]) != endpoint["MAC"] or event["ClientIP"] != client["ip"] or event["ServerIP"] != pod["ip"] or event["ServerPort"] != probe["port"] or event["IPProto"] != 6:
                    raise ValueError("native verdict has foreign scope")
                if probe.get("application", 0) and event.get("Application") != probe["application"]:
                    raise ValueError("nested HTTP application attribution missing")
                if event["PolicyAction"] != probe["action"] or event["PolicyID"] != probe["policy_id"] or event["FirstSeenAt"] < probe["started_at"]:
                    raise ValueError("native verdict does not belong to current reviewed probe")
        if probe["phase"] == "dp-stopped-bypass" and probe["queue_packets_after"] <= probe["queue_packets_before"]:
            raise ValueError("native-stop probe did not traverse retained bypass rules")
    if set(observations) != {probe["nonce"] for probe in probes if probe["allowed"]}:
        raise ValueError("unexpected requests or incomplete allowed cohort")
    summary = dict(passed=True, probes=len(probes), phases=sorted(expected_phases),
                   denied=sum(not probe["allowed"] for probe in probes),
                   observed=len(observations), native_verdict_probes=sum(probe["require_native"] for probe in probes),
                   boundary="single-node disposable Flannel; no off-host/real-node-failure or BPF proof")
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


class EvidenceContractTests(unittest.TestCase):
    def fixture(self, directory):
        identity = {"pods": [dict(name=name, namespace="proof", uid=name, ip=f"10.233.0.{index+10}")
                             for index, name in enumerate(("server-a", "server-b", "client"))]}
        endpoints = [dict(PodUID=pod["uid"], Namespace="proof", PodName=pod["name"],
                          IPs=[pod["ip"]], MAC=f"02:00:00:00:00:{index+1:02x}")
                     for index, pod in enumerate(identity["pods"][:2])]
        probes, logs = [], {"server-a": [], "server-b": []}
        phases = ("baseline", "monitor", "protect-a", "protect-b", "change-a", "dp-stopped-bypass")
        for phase in phases:
            for index, pod in enumerate(identity["pods"][:2]):
                for port in (18080, 18081):
                    native = phase not in ("baseline", "dp-stopped-bypass")
                    allowed, action, policy_id, application = expected_probe(phase, pod["name"], port)
                    deny = not allowed
                    nonce = f"{phase}-{pod['name']}-{port}"
                    source = 40000 + len(probes)
                    encoded_mac = base64.b64encode(bytes.fromhex(endpoints[index]["MAC"].replace(":", ""))).decode("ascii")
                    event = dict(EPMAC=encoded_mac, ClientIP="10.233.0.12", ServerIP=pod["ip"],
                                 ServerPort=port, IPProto=6, PolicyAction=action, PolicyID=policy_id, Application=application, FirstSeenAt=100)
                    probes.append(dict(phase=phase, pod=pod["name"], nonce=nonce, port=port, source_port=source,
                                       allowed=not deny, require_native=native, native=[event] if native else [],
                                       queue_packets_before=10, queue_packets_after=12, action=event["PolicyAction"],
                                       policy_id=event["PolicyID"], application=application, started_at=100))
                    if not deny:
                        logs[pod["name"]].append(dict(nonce=nonce, pod=pod["name"], port=port, remote=f"10.233.0.12:{source}"))
        evidence = dict(passed=True, identity=identity, endpoints=endpoints, probes=probes)
        path = Path(directory)
        (path / "driver-evidence").mkdir()
        self.persist(path, evidence, logs)
        return evidence, logs

    def persist(self, path, evidence, logs):
        (path / "driver-evidence" / "packet-evidence.json").write_text(json.dumps(evidence))
        for name, rows in logs.items():
            (path / f"{name}.log").write_text("".join(json.dumps(row)+"\n" for row in rows))

    def test_complete_evidence_and_negative_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, logs = self.fixture(directory)
            self.assertTrue(verify(directory)["passed"])
            for mutation in ("denied reached server", "missing native", "old aggregate", "foreign MAC", "no queue traversal", "wrong source"):
                with self.subTest(mutation=mutation):
                    changed, changed_logs = copy.deepcopy(evidence), copy.deepcopy(logs)
                    probe = next(row for row in changed["probes"] if not row["allowed"])
                    if mutation == "denied reached server":
                        changed_logs[probe["pod"]].append(dict(nonce=probe["nonce"], pod=probe["pod"], port=probe["port"], remote="10.233.0.12:40000"))
                    elif mutation == "missing native": probe["native"] = []
                    elif mutation == "old aggregate": probe["native"][0]["FirstSeenAt"] = 99
                    elif mutation == "foreign MAC": probe["native"][0]["EPMAC"] = "Av//////"
                    elif mutation == "no queue traversal": probe["queue_packets_after"] = probe["queue_packets_before"]
                    else: changed_logs["server-a"][0]["remote"] = "10.42.0.1:40000"
                    self.persist(Path(directory), changed, changed_logs)
                    with self.assertRaises(ValueError): verify(directory)

    def test_native_mac_wire_encoding_is_exact(self):
        self.assertEqual(native_mac("Bu3DyAQA"), "06:ed:c3:c8:04:00")
        self.assertEqual(native_mac("ikFLhfPT"), "8a:41:4b:85:f3:d3")
        for value in (None, [], "", "06:ed:c3:c8:04:00", "Bu3DyAQA\n", "Bu3DyAQ=", "Bu3DyAQA/w==", "!!!!!!", "é"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                native_mac(value)

    def test_scope_of_address(self):
        subnet = ipaddress.ip_network("10.233.0.0/16")
        self.assertIn(ipaddress.ip_address("10.233.1.4"), subnet)
        self.assertNotIn(ipaddress.ip_address("10.42.1.4"), subnet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("identity")
    identity.add_argument("directory")
    for field in ("cluster", "namespace", "node", "node-pidns", "node-netns", "host-pidns", "host-netns", "runtime-image"):
        identity.add_argument("--" + field, required=True)
    verifier = commands.add_parser("verify")
    verifier.add_argument("directory")
    commands.add_parser("self-test")
    arguments = parser.parse_args()
    if arguments.command == "identity":
        print(json.dumps(build_identity(arguments.directory, arguments), indent=2))
    elif arguments.command == "verify":
        print(json.dumps(verify(arguments.directory), indent=2))
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceContractTests)
        if not unittest.TextTestRunner().run(suite).wasSuccessful():
            raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"Flannel evidence rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
