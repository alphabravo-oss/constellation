"""Check the public API transport path and its NetworkPolicy admission."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class IngressChartTests(unittest.TestCase):
    def render(self, template, *values):
        command = ["helm", "template", "transport", str(ROOT / "deploy/charts/constellation"),
                   "--show-only", "templates/" + template]
        for value in values:
            command.extend(["--set", value])
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_api_bypasses_frontend_http_proxy(self):
        cases = [("ingress.yaml", "ingress.enabled=true", r"path: /api\s+pathType: Prefix"),
                 ("httproute.yaml", "gateway.enabled=true", r"value: /api")]
        for template, value, path in cases:
            with self.subTest(template=template):
                rendered = self.render(template, value, "api.service.port=8089")
                self.assertRegex(rendered, path)
                self.assertRegex(rendered, r"name: transport-constellation-api\s+(?:port:\s+number:|port:) 8089")
                self.assertIn("name: transport-constellation-frontend", rendered)
                disabled = self.render(template, value, "api.enabled=false")
                self.assertNotIn("name: transport-constellation-api", disabled)

    def test_api_admits_only_configured_ingress_network(self):
        for enabled in ("ingress.enabled=true", "gateway.enabled=true"):
            rendered = self.render("networkpolicies.yaml", enabled,
                "networkPolicies.enabled=true", "networkPolicies.frontendIngressCIDRs[0]=192.0.2.0/24")
            policies = rendered.split("\n---\n")
            api_policy = next(p for p in policies if "name: transport-constellation-api-ingress" in p)
            self.assertIn('cidr: "192.0.2.0/24"', api_policy)
            self.assertNotIn('cidr: "0.0.0.0/0"', api_policy)
            self.assertRegex(api_policy, r"protocol: TCP\s+port: 8080")
