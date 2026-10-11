"""Exercise actual Helm rendering for backup/recovery and rejected configurations."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy/charts/constellation"


class CNPGChartTests(unittest.TestCase):
    def render(self, *values, template=None, fails=False):
        command = ["helm", "template", "restore-test", str(CHART)]
        for value in values:
            command.extend(["--set", value])
        if template:
            command.extend(["--show-only", "templates/" + template])
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if fails:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            return result.stderr
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_plugin_backup(self):
        values = ("postgres.mode=cnpg", "postgres.cloudnativepg.barmanCloud.enabled=true",
                  "postgres.cloudnativepg.barmanCloud.objectStoreName=archive",
                  "postgres.cloudnativepg.scheduledBackup.enabled=true")
        cluster = self.render(*values, template="postgres-cnpg-cluster.yaml")
        self.assertIn("isWALArchiver: true", cluster)
        self.assertIn('barmanObjectName: "archive"', cluster)
        self.assertIn("initdb:", cluster)
        backup = self.render(*values, template="postgres-cnpg-scheduledbackup.yaml")
        self.assertIn("method: plugin", backup)
        self.assertIn("pluginConfiguration:", backup)

    def test_recovery_uses_existing_application_identity_and_pitr(self):
        cluster = self.render("postgres.mode=cnpg",
            "postgres.cloudnativepg.barmanCloud.recovery.enabled=true",
            "postgres.cloudnativepg.barmanCloud.recovery.objectStoreName=source-archive",
            "postgres.cloudnativepg.barmanCloud.recovery.serverName=source-postgres",
            "postgres.cloudnativepg.barmanCloud.recovery.targetTime=2026-10-11T10:00:00Z",
            template="postgres-cnpg-cluster.yaml")
        self.assertNotIn("initdb:", cluster)
        self.assertIn('database: "constellation"', cluster)
        self.assertIn('owner: "constellation"', cluster)
        self.assertIn("name: restore-test-constellation-postgres", cluster)
        self.assertIn('targetTime: "2026-10-11T10:00:00Z"', cluster)
        self.assertIn('serverName: "source-postgres"', cluster)

    def test_incomplete_or_conflicting_configuration_fails(self):
        cases = [
            (("postgres.cloudnativepg.barmanCloud.enabled=true",), "requires postgres.mode=cnpg"),
            (("postgres.mode=cnpg", "postgres.cloudnativepg.barmanCloud.enabled=true"), "objectStoreName is required"),
            (("postgres.mode=cnpg", "postgres.cloudnativepg.barmanCloud.recovery.enabled=true"), "recovery objectStoreName is required"),
            (("postgres.mode=cnpg", "postgres.cloudnativepg.barmanCloud.recovery.enabled=true",
              "postgres.cloudnativepg.barmanCloud.recovery.objectStoreName=source"), "recovery serverName is required"),
            (("postgres.mode=cnpg", "postgres.cloudnativepg.scheduledBackup.enabled=true"), "requires backup configuration"),
            (("postgres.mode=cnpg", "postgres.cloudnativepg.barmanCloud.enabled=true",
              "postgres.cloudnativepg.barmanCloud.objectStoreName=archive",
              "postgres.cloudnativepg.backup.retentionPolicy=30d"), "not both"),
        ]
        for values, message in cases:
            with self.subTest(values=values):
                self.assertIn(message, self.render(*values, fails=True))

    def test_default_mode_has_no_plugin_or_cnpg_cluster(self):
        rendered = self.render()
        self.assertNotIn("kind: Cluster\n", rendered)
        self.assertNotIn("kind: ScheduledBackup\n", rendered)
        self.assertIn("kind: StatefulSet\n", rendered)


if __name__ == "__main__":
    unittest.main()
