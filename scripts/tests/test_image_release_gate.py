import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

gate = load('gate', 'gate-image-release.py')
promoter = load('promoter', 'promote-gated-image.py')
DIGEST = 'sha256:'+'a'*64
CONFIG = 'sha256:'+'b'*64
IMAGE = 'example.test/team/image@'+DIGEST
IDENTITY = {'image': IMAGE, 'runtime_manifest': DIGEST, 'configuration': CONFIG}
NOW = dt.datetime.now(dt.timezone.utc)

def report():
    return {'source': {'type': 'image', 'target': {'userInput': IMAGE, 'imageID': CONFIG, 'os': 'linux', 'architecture': 'amd64'}},
            'descriptor': {'name': 'grype', 'version': 'test', 'configuration': {'search': {'scope': 'squashed'}},
                           'db': {'status': {'valid': True, 'built': NOW.isoformat(), 'from': 'https://example.test/db'}}},
            'matches': []}

def finding(severity='High', versions=None):
    return {'vulnerability': {'id': 'CVE-test', 'severity': severity, 'fix': {'state': 'fixed' if versions else '', 'versions': versions or []}},
            'artifact': {'name': 'library', 'version': '1.0'}}

class GateTests(unittest.TestCase):
    def test_fixable_high_and_critical_block(self):
        for severity in ['High', 'Critical']:
            data = report(); data['matches'] = [finding(severity, ['2.0'])]
            result = gate.evaluate(data, IDENTITY, NOW)
            self.assertFalse(result['passed']); self.assertEqual(len(result['blockers']), 1)

    def test_unfixed_and_medium_remain_visible(self):
        data = report(); data['matches'] = [finding('Critical'), finding('Medium', ['2.0'])]
        result = gate.evaluate(data, IDENTITY, NOW)
        self.assertTrue(result['passed']); self.assertEqual(result['counts'], {'critical': 1, 'medium': 1})

    def test_wrong_identity_suppression_filter_and_stale_db_refused(self):
        variants=[]
        data=report(); data['source']['target']['imageID']='sha256:'+'c'*64; variants.append(data)
        data=report(); data['source']['target']['userInput']='other'; variants.append(data)
        data=report(); data['source']['target']['architecture']='arm64'; variants.append(data)
        data=report(); data['ignoredMatches']=[finding()]; variants.append(data)
        for key,value in [('exclude',['/**']),('only-notfixed',True),('distro','other'),('vex-documents',['x'])]:
            data=report(); data['descriptor']['configuration'][key]=value; variants.append(data)
        for age in [dt.timedelta(days=6),dt.timedelta(minutes=-10)]:
            data=report(); data['descriptor']['db']['status']['built']=(NOW-age).isoformat();variants.append(data)
        data=report(); data['descriptor']['db']['status']['valid']=False; variants.append(data)
        data=report(); del data['matches']; variants.append(data)
        data=report(); data['matches']=[finding()];data['matches'][0]['vulnerability']['fix']['state']='fixed';variants.append(data)
        for data in variants:
            with self.subTest(data=data), self.assertRaises((ValueError,KeyError)):
                gate.evaluate(data,IDENTITY,NOW)

    def test_index_allows_attestation_but_not_unscanned_platforms(self):
        runtime={'digest':DIGEST,'platform':{'os':'linux','architecture':'amd64'}}
        attestation={'digest':'sha256:'+'d'*64,'platform':{'os':'unknown','architecture':'unknown'},'annotations':{'vnd.docker.reference.type':'attestation-manifest'}}
        root={'manifests':[runtime,attestation]}
        with patch.object(gate,'checked',side_effect=[json.dumps(root),json.dumps({'config':{'digest':CONFIG}})]):
            self.assertEqual(gate.image_identity(IMAGE),IDENTITY)
        root['manifests'].append({'digest':'sha256:'+'e'*64,'platform':{'os':'linux','architecture':'arm64'}})
        with patch.object(gate,'checked',return_value=json.dumps(root)),self.assertRaises(ValueError):
            gate.image_identity(IMAGE)

    def test_failed_scan_removes_previous_passing_receipt_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            scan = pathlib.Path(directory)/'scan.json'
            receipt = pathlib.Path(directory)/'receipt.json'
            scan.write_text('{}'); receipt.write_text('{"passed":true}')
            args = ['gate', '--image', IMAGE, '--report', str(scan), '--receipt', str(receipt)]
            with patch.object(gate.sys, 'argv', args), patch.object(gate, 'image_identity', return_value=IDENTITY), patch.object(gate.subprocess, 'run', side_effect=gate.subprocess.CalledProcessError(1, 'grype')) as run, patch.dict(gate.os.environ, {'GRYPE_ONLY_NOTFIXED': 'true', 'SYFT_EXCLUDE': '/**'}):
                with self.assertRaises(gate.subprocess.CalledProcessError):
                    gate.main()
            self.assertFalse(receipt.exists())
            self.assertFalse(scan.exists())
            self.assertFalse(any(key.startswith(('GRYPE_', 'SYFT_')) for key in run.call_args.kwargs['env']))

    def test_mutable_tag_rejected_without_network(self):
        with patch.object(gate,'checked') as checked,self.assertRaises(ValueError):gate.image_identity('example.test/image:latest')
        checked.assert_not_called()

class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.directory=pathlib.Path(self.temp.name);self.report=self.directory/'report.json';self.receipt=self.directory/'receipt.json'
        self.data=report();self.write()
        self.identity=patch.object(promoter.gate,'image_identity',return_value=IDENTITY).start();self.addCleanup(patch.stopall)
        self.command=patch.object(promoter.gate,'checked').start()
        self.remote=patch.object(promoter.publisher,'remote_digest',side_effect=[None,DIGEST]).start()

    def write(self):
        self.report.write_text(json.dumps(self.data))
        self.receipt.write_text(json.dumps({**IDENTITY,'passed':True,'report_sha256':hashlib.sha256(self.report.read_bytes()).hexdigest()}))

    def promote(self):return promoter.promote(IMAGE,'example.test/team/image:v1',self.report,self.receipt)

    def test_exact_digest_promoted_after_gate(self):
        self.assertTrue(self.promote()['verified'])
        self.command.assert_called_once_with('docker','buildx','imagetools','create','--prefer-index=false','--tag','example.test/team/image:v1',IMAGE)

    def test_forged_pass_flag_cannot_override_findings(self):
        self.data['matches']=[finding('Critical',['2.0'])];self.write()
        with self.assertRaises(ValueError):self.promote()
        self.command.assert_not_called();self.remote.assert_not_called()

    def test_report_changed_after_gate_cannot_promote(self):
        self.report.write_text('{}')
        with self.assertRaises(ValueError):self.promote()
        self.command.assert_not_called()

    def test_existing_release_cannot_be_overwritten(self):
        self.remote.side_effect=None;self.remote.return_value='sha256:'+'e'*64
        with self.assertRaises(ValueError):self.promote()
        self.command.assert_not_called()

    def test_idempotent_promotion_does_not_write(self):
        self.remote.side_effect=None;self.remote.return_value=DIGEST
        self.assertTrue(self.promote()['verified']);self.command.assert_not_called()

    def test_changed_remote_digest_is_not_success(self):
        self.remote.side_effect=[None,'sha256:'+'e'*64]
        with self.assertRaises(ValueError):self.promote()

if __name__=='__main__':unittest.main()
