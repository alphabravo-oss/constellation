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
            'custom-system', '--set-json', 'systemProtection='+json.dumps(values),
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
