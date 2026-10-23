#!/usr/bin/env bash
# Contract for optional identity, external OIDC and independent local accounts.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chart=deploy/charts/constellation
helm template constellation "$chart" > "$work/local.yaml"
helm template constellation "$chart" --set identity.enabled=true > "$work/bundled.yaml"
helm template constellation "$chart" --set auth.oidc.enabled=true \
 --set auth.oidc.issuerURL=https://customer.example --set auth.oidc.clientID=customer \
 --set auth.oidc.redirectURL=https://product.example/callback > "$work/external.yaml"
python3 - "$work" <<'PY'
import pathlib,sys,yaml
root=pathlib.Path(sys.argv[1])
def render(name):return [x for x in yaml.safe_load_all((root/f'{name}.yaml').read_text()) if x]
def env(items):
 api=next(x for x in items if x['kind']=='Deployment' and x['metadata']['name']=='constellation-api')
 return {e['name']:e for e in api['spec']['template']['spec']['containers'][0]['env']}
local,bundled,external=map(render,['local','bundled','external'])
assert not any('identity' in x['metadata']['name'] for x in local)
assert 'OIDC_ISSUER_URL' not in env(local)
e=env(bundled)
assert e['LOCAL_AUTH_ENABLED']['value']=='true'
assert e['OIDC_BUNDLED']['value']=='true'
for name,key in [('OIDC_ISSUER_URL','issuer'),('OIDC_CLIENT_ID','client-id'),('OIDC_CLIENT_SECRET','client-secret')]:
 assert e[name]['valueFrom']['secretKeyRef']=={'name':'constellation-identity-product-constellation','key':key}
assert e['OIDC_REDIRECT_URL']['value']=='https://identity.example.com/api/v1/auth/oidc/callback'
assert e['OIDC_ROLE_MAPPING']['value']=='{"analyst":"Analyst","security-admin":"SecurityAdmin"}'
registry=next(x for x in bundled if x['kind']=='ConfigMap' and x['metadata']['name']=='constellation-identity-products')
assert '{{' not in registry['data']['products.json']
policy=next(x for x in bundled if x['kind']=='NetworkPolicy' and x['metadata']['name']=='constellation-identity-egress')
assert policy['spec']['podSelector'] # Never broaden the whole parent namespace.
assert env(external)['OIDC_ISSUER_URL']['value']=='https://customer.example'
assert env(external)['OIDC_CLIENT_ID']['value']=='customer'
assert 'OIDC_BUNDLED' not in env(external)
print('identity chart: local-only, bundled, external and scoped policies passed')
PY
