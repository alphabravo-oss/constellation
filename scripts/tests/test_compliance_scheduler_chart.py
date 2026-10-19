"""Scheduler signing and artifact sharing must be explicit and least privilege."""
import pathlib
import subprocess
import unittest
import yaml

CHART = pathlib.Path(__file__).resolve().parents[2] / 'deploy/charts/constellation'

class ComplianceSchedulerChartTests(unittest.TestCase):
    def render(self, *values):
        cmd = ['helm', 'template', 'proof', str(CHART)]
        for value in values:
            cmd += ['--set', value]
        return subprocess.run(cmd, capture_output=True, text=True)

    def enabled(self, *extra):
        result = self.render('complianceScheduler.enabled=true',
            'complianceScheduler.storage.existingClaim=report-pvc',
            'complianceScheduler.signingSecret=report-key', *extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        docs = list(yaml.safe_load_all(result.stdout))
        return {d['metadata']['name']: d for d in docs if d and d['kind'] == 'Deployment'}

    def test_default_is_disabled_and_missing_prerequisites_fail(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('name: proof-constellation-compliance-scheduler', result.stdout)
        for extra in [[], ['complianceScheduler.storage.existingClaim=reports'],
                      ['complianceScheduler.storage.existingClaim=reports', 'complianceScheduler.signingSecret=key', 'api.enabled=false']]:
            result = self.render('complianceScheduler.enabled=true', *extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('complianceScheduler', result.stderr)

    def test_shared_storage_readonly_api_and_private_signer(self):
        docs = self.enabled('api.env.REPORT_OUT_DIR=/wrong')
        api = next(d for n, d in docs.items() if n.endswith('-api'))
        worker = next(d for n, d in docs.items() if n.endswith('-compliance-scheduler'))
        api_spec = api['spec']['template']['spec']
        spec = worker['spec']['template']['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertEqual(worker['spec']['replicas'], 1)
        self.assertEqual(api['spec']['strategy']['type'], 'Recreate')
        self.assertIn('podAffinity', spec['affinity'])
        api_c = api_spec['containers'][0]
        worker_c = spec['containers'][0]
        for c in [api_c, worker_c]:
            roots = [e['value'] for e in c['env'] if e['name'] == 'REPORT_OUT_DIR']
            self.assertEqual(roots, ['/var/lib/constellation-reports/reports'])
            self.assertTrue(c['securityContext']['runAsNonRoot'])
            self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        api_mount = next(v for v in api_c['volumeMounts'] if v['name'] == 'compliance-reports')
        self.assertTrue(api_mount['readOnly'])
        self.assertNotIn('report-key', str(api_spec))
        self.assertIn('report-key', str(spec))
        self.assertIn('/compliance-scheduler:', worker_c['image'])

    def test_shared_multi_node_storage_does_not_force_colocation(self):
        docs = self.enabled('complianceScheduler.storage.accessMode=ReadWriteMany')
        worker = next(d for n, d in docs.items() if n.endswith('-compliance-scheduler'))
        self.assertNotIn('affinity', worker['spec']['template']['spec'])

if __name__ == '__main__':
    unittest.main()
