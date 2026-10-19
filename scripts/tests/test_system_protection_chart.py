"""Shared dependency protection reaches every enforcement consumer."""
import json
import pathlib
import subprocess
import unittest
import yaml

CHART = pathlib.Path(__file__).resolve().parents[2] / 'deploy/charts/constellation'
CORE = {'custom-system', 'kube-system', 'kube-public', 'kube-node-lease'}

class SystemProtectionChartTests(unittest.TestCase):
    def render(self, values):
        return subprocess.run(['helm', 'template', 'protection', str(CHART), '-n',
            'custom-system', '--set', 'clusterRegistration.clusterId=11111111-1111-4111-8111-111111111111', '--set-json', 'systemProtection='+json.dumps(values),
            '--set', 'runtimeAgent.enforcement.protectedNamespaces[0]=runtime-extra',
            '--set', 'networkPolicyApplier.protectedNamespaces[0]=network-extra',
            '--set', 'admission.webhook.namespaceSelector.matchLabels.enforce=yes'],
            text=True, capture_output=True)

    def test_shared_and_legacy_additions_preserve_mandatory_protection(self):
        for extras in [[], ['cnpg-system'], ['custom-system', 'cnpg-system']]:
            with self.subTest(extras=extras):
                result=self.render({'protectedNamespaces': extras})
                self.assertEqual(result.returncode, 0, result.stderr)
                docs=list(yaml.safe_load_all(result.stdout))
                api=next(d for d in docs if d and d['kind']=='Deployment' and d['metadata']['name'].endswith('-api'))
                env=api['spec']['template']['spec']['containers'][0]['env']
                protected=json.loads(next(e['value'] for e in env if e['name']=='CONSTELLATION_QUARANTINE_PROTECTED_NAMESPACES'))
                self.assertEqual(set(protected), {'11111111-1111-4111-8111-111111111111'})
                self.assertEqual(set(next(iter(protected.values()))), CORE | set(extras))
                webhook=next(d for d in docs if d and d['kind']=='ValidatingWebhookConfiguration')
                selector=webhook['webhooks'][0]['namespaceSelector']
                expr=selector['matchExpressions'][0]
                self.assertEqual(expr['operator'], 'NotIn')
                self.assertEqual(expr['key'], 'kubernetes.io/metadata.name')
                self.assertEqual(set(expr['values']), CORE | set(extras))
                self.assertEqual(selector['matchLabels'], {'enforce':'yes'})
                for component, extra in [('runtime-agent','runtime-extra'), ('network-policy-applier','network-extra')]:
                    doc=next(d for d in docs if d and d['kind'] in ['Deployment','DaemonSet'] and d['metadata']['name'].endswith(component))
                    env=doc['spec']['template']['spec']['containers'][0]['env']
                    value=next(e['value'] for e in env if e['name']=='CONSTELLATION_ENFORCEMENT_PROTECTED_NAMESPACES')
                    self.assertEqual(set(value.split(',')), CORE | set(extras) | {extra})
                    self.assertEqual(len(value.split(',')),len(set(value.split(','))))

    def test_invalid_namespace_configuration_is_rejected(self):
        for bad in [[''], ['a,b'], ['UPPER'], ['a'*64], 'cnpg-system']:
            with self.subTest(bad=bad):
                result=self.render({'protectedNamespaces':bad})
                self.assertNotEqual(result.returncode,0)
                self.assertIn('systemProtection',result.stderr)

    def test_unbound_install_does_not_guess_a_cluster_for_api_protection(self):
        result=subprocess.run(['helm','template','protection',str(CHART),'--show-only','templates/api-deployment.yaml'],text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('CONSTELLATION_QUARANTINE_PROTECTED_NAMESPACES',result.stdout)

    def test_default_webhook_covers_ephemeral_container_updates(self):
        result=self.render({'protectedNamespaces':['cnpg-system']})
        self.assertEqual(result.returncode,0,result.stderr)
        webhook=next(d for d in yaml.safe_load_all(result.stdout) if d and d['kind']=='ValidatingWebhookConfiguration')['webhooks'][0]
        self.assertTrue(any('pods/ephemeralcontainers' in rule['resources'] and 'UPDATE' in rule['operations'] and '' in rule['apiGroups'] for rule in webhook['rules']))
        self.assertIn('cnpg-system',webhook['namespaceSelector']['matchExpressions'][0]['values'])
