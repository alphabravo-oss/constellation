"""Dedicated discoverer credentials must reach env and projected token reads."""
import pathlib
import subprocess
import unittest
import yaml

CHART = pathlib.Path(__file__).resolve().parents[2] / 'deploy/charts/constellation'

class DiscovererCredentialsChartTests(unittest.TestCase):
    def test_credential_sources_and_other_consumers(self):
        for settings, expected, runtime in [([], 'enroll-runtime-agent-token', 'enroll-runtime-agent-token'),
                (['runtimeAgent.tokenSecret=shared-agent'], 'shared-agent', 'shared-agent'),
                (['runtimeAgent.tokenSecret=shared-agent', 'discoverer.tokenSecret=discovery-agent'], 'discovery-agent', 'shared-agent')]:
            with self.subTest(settings=settings):
                args = ['helm', 'template', 'enroll', str(CHART)]
                for setting in settings:
                    args += ['--set', setting]
                rendered = subprocess.run(args, text=True, capture_output=True, check=True)
                docs = [d for d in yaml.safe_load_all(rendered.stdout) if d]
                discoverer = next(d for d in docs if d['kind']=='Deployment' and d['metadata']['name']=='enroll-constellation-discoverer')
                spec = discoverer['spec']['template']['spec']
                # Release fullname includes the chart name unless already present.
                expected = expected.replace('enroll-runtime', 'enroll-constellation-runtime')
                runtime = runtime.replace('enroll-runtime', 'enroll-constellation-runtime')
                env = spec['containers'][0]['env']
                for name in ['CONSTELLATION_DISCOVERER_TOKEN', 'RUNTIME_AGENT_TOKEN']:
                    self.assertEqual(next(e for e in env if e['name']==name)['valueFrom']['secretKeyRef']['name'], expected)
                self.assertEqual(next(v for v in spec['volumes'] if v['name']=='runtime-agent-token')['secret']['secretName'], expected)
                agent = next(d for d in docs if d['kind']=='DaemonSet' and d['metadata']['name']=='enroll-constellation-runtime-agent')
                self.assertEqual(next(v for v in agent['spec']['template']['spec']['volumes'] if v['name']=='runtime-agent-token-file')['secret']['secretName'], runtime)
