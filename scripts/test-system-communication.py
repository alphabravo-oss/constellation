#!/usr/bin/env python3
"""Opt-in disposable network-policy proof of protected communication and app isolation.

Requires a hosted-built internal/netpolicyapply test binary, kubectl, and a pinned
migration image containing BusyBox. Never applies policies to existing namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid


def kubectl(*args, data=None, check=True, timeout=100):
    return subprocess.run(['kubectl', *args], input=None if data is None else json.dumps(data),
                          capture_output=True, text=True, check=check, timeout=timeout)


def get(kind, name, namespace=None):
    args = ['get', kind, name, '-o', 'json']
    if namespace:
        args += ['-n', namespace]
    return json.loads(kubectl(*args).stdout)


def create(obj):
    kubectl('create', '-f', '-', data=obj)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flavor', choices=['native', 'cilium', 'calico'], default='native')
    parser.add_argument('--live', action='store_true', required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--client-node')
    parser.add_argument('--peer-node')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}', args.image):
        raise ValueError('fixture image must be digest pinned')
    if bool(args.client_node) != bool(args.peer_node) or (args.client_node and args.client_node == args.peer_node):
        raise ValueError('cross-node proof requires two distinct explicit node names')
    args.output.mkdir(parents=True, exist_ok=True)
    nonce = uuid.uuid4().hex[:10]
    app = 'constellation-policy-proof-app-' + nonce
    system = 'constellation-policy-proof-system-' + nonce
    label = 'constellation.alphabravo.io/protection-proof'
    owned = {}
    policy_kind = {'cilium': 'ciliumnetworkpolicy', 'calico': 'globalnetworkpolicies.projectcalico.org', 'native': 'networkpolicy'}[args.flavor]
    policy_name = 'communication-proof-' + nonce if args.flavor == 'calico' else 'communication-proof'
    policy_namespace = None if args.flavor == 'calico' else app
    policy_scope = [] if args.flavor == 'calico' else ['-n', app]
    evidence = {'nonce': nonce, 'namespaces': [app, system], 'image': args.image, 'flavor': args.flavor, 'probes': []}

    def probe(namespace, pod, target, expected, tag):
        result = kubectl('exec', '-n', namespace, pod, '--', '/bin/busybox', 'wget', '-T', '3', '-qO-',
                         target, check=False, timeout=10)
        success = result.returncode == 0 and result.stdout.strip() == 'ok'
        evidence['probes'].append({'tag': tag, 'sourceNamespace': namespace, 'sourcePod': pod,
                                   'target': target, 'expectedAllowed': expected, 'allowed': success,
                                   'exitCode': result.returncode, 'stderr': result.stderr[-500:]})
        print(json.dumps({'probe': tag, 'expectedAllowed': expected, 'allowed': success}), flush=True)
        if expected != success:
            raise AssertionError(f'{tag}: expected allowed={expected}, got {success}: {result.stderr}')

    def pod(namespace, name, role):
        serve = "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok' | nc -l -p PORT -w 2; done"
        command = '(' + serve.replace('PORT', '18080') + ') & (' + serve.replace('PORT', '18081') + ') & wait'
        obj = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace, 'labels': {'proof-role': role}},
                'spec': {'automountServiceAccountToken': False, 'terminationGracePeriodSeconds': 1, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001},
                         'containers': [{'name': 'fixture', 'image': args.image, 'command': ['/bin/sh', '-c', command],
                                         'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                                         'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}}}]}}
        if args.client_node:
            obj['spec']['nodeName'] = args.client_node if name == 'client' else args.peer_node
        return obj

    try:
        for namespace in [app, system]:
            create({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace, 'labels': {label: nonce}}})
            owned[namespace] = get('namespace', namespace)['metadata']['uid']
        for namespace, name, role in [(app, 'client', 'client'), (app, 'ordinary', 'ordinary'), (system, 'protected', 'protected')]:
            create(pod(namespace, name, role))
        create({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'protected', 'namespace': system},
                'spec': {'selector': {'proof-role': 'protected'}, 'ports': [{'port': 18080, 'targetPort': 18080}]}})
        create({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'ordinary', 'namespace': app},
                'spec': {'type': 'NodePort', 'selector': {'proof-role': 'ordinary'}, 'ports': [{'port': 18080, 'targetPort': 18080}]}})
        for namespace in [app, system]:
            kubectl('wait', '-n', namespace, '--for=condition=Ready', 'pod', '--all', '--timeout=90s')
        client = get('pod', 'client', app)
        ordinary = get('pod', 'ordinary', app)
        protected = get('pod', 'protected', system)
        ordinary_ip = ordinary['status']['podIP']
        protected_ip = protected['status']['podIP']
        evidence['placement'] = {name: {'node': item['spec']['nodeName'], 'ip': item['status']['podIP']}
                                 for name, item in [('client', client), ('ordinary', ordinary), ('protected', protected)]}
        if args.client_node:
            if (client['spec']['nodeName'] != args.client_node or ordinary['spec']['nodeName'] != args.peer_node
                    or protected['spec']['nodeName'] != args.peer_node):
                raise AssertionError('cross-node placement was not honored')
            evidence['crossNodeVerified'] = True
        client_ip = client['status']['podIP']
        protected_service = get('service', 'protected', system)['spec']['clusterIP']
        node = get('node', client['spec']['nodeName'])
        node_ip = next(a['address'] for a in node['status']['addresses'] if a['type'] == 'InternalIP')
        node_port = get('service', 'ordinary', app)['spec']['ports'][0]['nodePort']
        # A protected dependency shares the ordinary application's IP, but only
        # port 18081 is declared. Its unrelated port 18080 must stay blocked.
        create({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'shared-endpoint', 'namespace': system},
                'spec': {'ports': [{'name': 'dependency', 'port': 18081, 'targetPort': 18081}]}})
        shared = get('service', 'shared-endpoint', system)
        create({'apiVersion': 'discovery.k8s.io/v1', 'kind': 'EndpointSlice',
                'metadata': {'name': 'shared-endpoint-proof', 'namespace': system,
                             'labels': {'kubernetes.io/service-name': 'shared-endpoint'},
                             'ownerReferences': [{'apiVersion': 'v1', 'kind': 'Service', 'name': 'shared-endpoint', 'uid': shared['metadata']['uid']}]},
                'addressType': 'IPv4', 'ports': [{'name': 'dependency', 'protocol': 'TCP', 'port': 18081}],
                'endpoints': [{'addresses': [ordinary_ip], 'conditions': {'ready': True}}]})
        targets = {'protectedPod': f'http://{protected_ip}:18080/', 'protectedService': f'http://{protected_service}:18080/',
                   'sharedRequiredPort': f'http://{ordinary_ip}:18081/', 'ordinaryPod': f'http://{ordinary_ip}:18080/',
                   'ordinaryNodePort': f'http://{node_ip}:{node_port}/'}
        if args.peer_node:
            peer = get('node', args.peer_node)
            peer_ip = next(a['address'] for a in peer['status']['addresses'] if a['type'] == 'InternalIP')
            targets['ordinaryRemoteNodePort'] = f'http://{peer_ip}:{node_port}/'
        for tag, target in targets.items():
            probe(app, 'client', target, True, 'baseline-' + tag)
        probe(app, 'ordinary', f'http://{client_ip}:18080/', True, 'baseline-ordinary-ingress')
        if args.flavor == 'calico':
            probe(system, 'protected', targets['ordinaryPod'], True, 'baseline-system-egress')
        # DNS transport is required, but its colocated metrics port must not
        # inherit a blanket kube-system communication exception.
        dns_service = get('service', 'kube-dns', 'kube-system')
        metrics_port = next(p['port'] for p in dns_service['spec']['ports'] if p.get('name') == 'metrics')
        metrics_url = f"http://{dns_service['spec']['clusterIP']}:{metrics_port}/metrics"
        metrics = kubectl('exec', '-n', app, 'client', '--', 'wget', '-T', '3', '-qO', '/dev/null', metrics_url, check=False, timeout=10)
        if metrics.returncode:
            raise AssertionError('DNS metrics baseline is not reachable; this fixture requires its explicit positive control')
        env = dict(os.environ, CONSTELLATION_POLICY_PROOF_NAMESPACE=app, CONSTELLATION_POLICY_PROOF_FLAVOR=args.flavor,
                   CONSTELLATION_POLICY_PROOF_PROTECTED_NAMESPACE=system, CONSTELLATION_POLICY_PROOF_NONCE=nonce)
        if args.flavor == 'cilium':
            # A second pod with the same Cilium identity must not inherit the
            # selectorless dependency's port. Refuse before creating a policy.
            create(pod(app, 'shadow', 'ordinary'))
            kubectl('wait', '-n', app, '--for=condition=Ready', 'pod/shadow', '--timeout=90s')
            for _ in range(30):
                status = kubectl('get', 'ciliumendpoint', 'shadow', '-n', app, '-o', 'json', check=False)
                if status.returncode == 0 and json.loads(status.stdout).get('status', {}).get('identity', {}).get('id', 0) >= 256:
                    break
                time.sleep(1)
            else:
                raise AssertionError('shadow Cilium identity did not converge')
            refused = subprocess.run([str(args.helper.resolve()), '-test.run', '^TestApplyNativeCommunicationLive$', '-test.v'],
                                     env=env, text=True, capture_output=True, timeout=45)
            (args.output/'shared-identity-refusal.log').write_text(refused.stdout + refused.stderr)
            if refused.returncode == 0 or 'also selects unrelated endpoint' not in refused.stdout:
                raise AssertionError('shared identity did not produce the expected explicit refusal')
            existing = kubectl('get', policy_kind, 'communication-proof', '-n', app, '--ignore-not-found', '-o', 'json')
            if existing.stdout.strip():
                raise AssertionError('refused policy was written')
            evidence['sharedIdentityRefusedBeforeWrite'] = True
            kubectl('delete', 'pod', 'shadow', '-n', app, '--wait=true', '--timeout=60s')
            for _ in range(30):
                gone = kubectl('get', 'ciliumendpoint', 'shadow', '-n', app, '--ignore-not-found', '-o', 'json')
                if not gone.stdout.strip():
                    break
                time.sleep(1)
            else:
                raise AssertionError('shadow Cilium endpoint was not removed')
        result = subprocess.run([str(args.helper.resolve()), '-test.run', '^TestApplyNativeCommunicationLive$', '-test.v'],
                                env=env, text=True, capture_output=True, timeout=45)
        (args.output/'helper.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError('guarded apply failed; see helper.log')
        evidence['effectivePolicy'] = get(policy_kind, policy_name, policy_namespace)
        time.sleep(5)  # Bounded dataplane convergence before fresh TCP probes.
        for repeat in range(3):
            for tag, target in targets.items():
                probe(app, 'client', target, not tag.startswith('ordinary'), f'protected-{repeat}-{tag}')
            probe(system, 'protected', f'http://{client_ip}:18080/', True, f'protected-{repeat}-system-ingress')
            probe(app, 'ordinary', f'http://{client_ip}:18080/', False, f'protected-{repeat}-ordinary-ingress')
            if args.flavor == 'calico':
                probe(system, 'protected', targets['ordinaryPod'], True, f'protected-{repeat}-excluded-system-egress')
        dns = kubectl('exec', '-n', app, 'client', '--', 'nslookup', 'kubernetes.default.svc.cluster.local', check=False, timeout=10)
        if dns.returncode:
            raise AssertionError('DNS unavailable under isolation: ' + dns.stderr)
        evidence['dnsSucceeded'] = True
        metrics = kubectl('exec', '-n', app, 'client', '--', 'wget', '-T', '3', '-qO', '/dev/null', metrics_url, check=False, timeout=10)
        if metrics.returncode == 0:
            raise AssertionError('Non-DNS core service port bypassed isolation')
        evidence['coreMetricsBlockedWithDNSWorking'] = True
        api = kubectl('exec', '-n', app, 'client', '--', 'wget', '-T', '3', '-S', '--no-check-certificate', '-O', '-',
                      'https://kubernetes.default.svc.cluster.local/version', check=False, timeout=10)
        if not re.search(r'HTTP/\S+ (200|401|403)', api.stderr):
            raise AssertionError('Kubernetes API transport unavailable: ' + api.stderr)
        evidence['apiTransportSucceeded'] = True
        if args.flavor == 'calico' and env.get('CONSTELLATION_POLICY_PROOF_SERVICE_ACCOUNT'):
            removal = subprocess.run([str(args.helper.resolve()), '-test.run', '^TestApplyNativeCommunicationLive$', '-test.v'],
                                     env=dict(env, CONSTELLATION_POLICY_PROOF_ACTION='delete'), text=True, capture_output=True, timeout=45)
            (args.output/'delete-helper.log').write_text(removal.stdout + removal.stderr)
            if removal.returncode:
                raise AssertionError('service-account recovery deletion failed; see delete-helper.log')
            evidence['serviceAccountApplyAndDelete'] = env['CONSTELLATION_POLICY_PROOF_SERVICE_ACCOUNT']
        else:
            kubectl('delete', policy_kind, policy_name, *policy_scope)
        time.sleep(5)
        probe(app, 'client', targets['ordinaryPod'], True, 'recovery-ordinary-egress')
        probe(app, 'ordinary', f'http://{client_ip}:18080/', True, 'recovery-ordinary-ingress')
        evidence['passed'] = True
    finally:
        cleanup_errors = []
        if args.flavor == 'calico':
            try:
                found = kubectl('get', policy_kind, policy_name, '--ignore-not-found', '-o', 'json')
                if found.stdout.strip():
                    obj = json.loads(found.stdout)
                    if obj['metadata'].get('labels', {}).get(label) != nonce:
                        raise RuntimeError('global fixture policy ownership changed; refusing deletion')
                    kubectl('delete', policy_kind, policy_name, '--wait=true', '--timeout=30s')
                evidence['globalPolicyCleanupComplete'] = True
            except Exception as exc:
                cleanup_errors.append(str(exc))
        for namespace, uid in owned.items():
            try:
                current = get('namespace', namespace)
                if current['metadata']['uid'] != uid or current['metadata'].get('labels', {}).get(label) != nonce:
                    raise RuntimeError('fixture ownership changed; refusing deletion')
                kubectl('delete', 'namespace', namespace, '--wait=true', '--timeout=60s', timeout=70)
            except Exception as exc:
                cleanup_errors.append(str(exc))
        evidence['cleanupErrors'] = cleanup_errors
        (args.output/'evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
        if cleanup_errors:
            raise RuntimeError('fixture cleanup failed: ' + '; '.join(cleanup_errors))
    print(json.dumps({'passed': evidence['passed'], 'probes': len(evidence['probes']), 'dns': True, 'apiTransport': True, 'cleanup': 'complete'}))


if __name__ == '__main__':
    main()
