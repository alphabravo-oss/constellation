export function operatorStorageKey(key: string, identity: { org_id: string; user_id: string } | null) {
  return identity ? `constellation.operator.${JSON.stringify([identity.org_id, identity.user_id, key])}` : null;
}
