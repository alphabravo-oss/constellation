package complianceevidence

// Source identities and mapping projections are normalized before filters,
// summaries or pagination. No source LIMIT can starve a later evidence scope.
const evidenceInventorySQL = `
WITH mappings AS (SELECT * FROM jsonb_to_recordset($4::jsonb) AS m(internal_id text,framework text,control_id text,title text,severity text,tags jsonb)),
host_rules AS (SELECT * FROM jsonb_to_recordset($5::jsonb) AS h(control_id text,internal_id text,severity text,remediation text)),
artifact_input(source_id,owner_target,cluster_id,namespace,name,kind,image_ref,image_digest,result_id,observed_at,secret_count,secret_status,file_risk_count,file_risk_status,severity_rank,risk_types) AS (

SELECT l.id, CASE WHEN l.workload_id=ANY($6::text[]) THEN l.workload_id ELSE l.namespace||'/'||l.name END, l.cluster_id,
       l.namespace,
       l.name,
       l.kind,
       l.image_ref,
       COALESCE(l.image_digest, ''),
       r.id,
       COALESCE(r.last_scanned_at, l.last_seen_at),
       COALESCE(sec.secret_count, -1)::int,
       COALESCE(sec.status, ''),
       COALESCE(fr.file_risk_count, -1)::int,
       COALESCE(fr.status, ''),
       COALESCE(fr.max_severity_rank, 0)::int,
       COALESCE(fr.risk_types, '')
  FROM image_workload_links l
  LEFT JOIN LATERAL (
        SELECT r.id, r.last_scanned_at
          FROM image_scan_results r
         WHERE r.org_id = l.org_id
           AND (
                (COALESCE(l.image_digest, '') <> '' AND r.image_digest = l.image_digest)
             OR (COALESCE(l.image_digest, '') = '' AND (
                    (l.image_ref <> '' AND r.image_ref = l.image_ref)
                 OR (l.image_ref_normalized <> '' AND r.image_ref_normalized = l.image_ref_normalized)
                ))
           )
         ORDER BY r.last_scanned_at DESC, r.updated_at DESC, r.id DESC
         LIMIT 1
       ) r ON TRUE
  LEFT JOIN LATERAL (
        SELECT COALESCE(NULLIF(a.payload->>'secret_count', '')::int, a.package_count) AS secret_count,
               COALESCE(NULLIF(a.payload->>'status', ''), 'observed') AS status
          FROM image_scan_artifacts a
         WHERE a.org_id = l.org_id
           AND a.image_scan_result_id = r.id
           AND a.artifact_type = 'secret-scan'
           AND a.format = 'constellation-image-secrets-v1'
         ORDER BY a.created_at DESC, a.id DESC
         LIMIT 1
       ) sec ON TRUE
  LEFT JOIN LATERAL (
        SELECT COALESCE(NULLIF(a.payload->>'file_risk_count', '')::int, a.package_count) AS file_risk_count,
               COALESCE(NULLIF(a.payload->>'status', ''), 'observed') AS status,
               COALESCE((
                   SELECT MAX(CASE lower(f.value->>'severity')
                                WHEN 'critical' THEN 5
                                WHEN 'high' THEN 4
                                WHEN 'medium' THEN 3
                                WHEN 'low' THEN 2
                                ELSE 1
                              END)::int
                     FROM jsonb_array_elements(COALESCE(a.payload->'findings', '[]'::jsonb)) AS f(value)
               ), 0)::int AS max_severity_rank,
               COALESCE((
                   SELECT string_agg(DISTINCT rt.value, ',')
                     FROM jsonb_array_elements(COALESCE(a.payload->'findings', '[]'::jsonb)) AS f(value)
                     CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(f.value->'risk_types', '[]'::jsonb)) AS rt(value)
               ), '') AS risk_types
          FROM image_scan_artifacts a
         WHERE a.org_id = l.org_id
           AND a.image_scan_result_id = r.id
           AND a.artifact_type = 'file-risk'
           AND a.format = 'constellation-image-file-risk-v1'
         ORDER BY a.created_at DESC, a.id DESC
         LIMIT 1
       ) fr ON TRUE
 WHERE l.org_id = $1
   AND (l.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=l.cluster_id AND org_id=$1))
   AND ($6::text[] IS NULL OR l.workload_id=ANY($6) OR (l.namespace||'/'||l.name)=ANY($6))
   AND ($2::uuid IS NULL OR l.cluster_id = $2)
   AND ($3::text = '' OR l.namespace = $3)
),
raw_rows(source_id,scope,source,internal_id,default_framework,default_control,title,severity,status,target_kind,target,owner_target,cluster_id,namespace,evidence,remediation,observed_at,tags,mapped) AS (
 SELECT 'check:'||cc.id,'kubernetes','compliance_checks','',cc.framework,cc.control_id,cc.title,cc.severity,cc.status,'cluster','cluster','cluster',cc.cluster_id,'',COALESCE(NULLIF(cc.evidence,''),cc.description,''),'',cc.evaluated_at,COALESCE(cc.tags_v2,'{}'::jsonb),false
 FROM compliance_checks cc WHERE cc.org_id=$1 AND ($2::uuid IS NULL OR cc.cluster_id=$2)
 AND (cc.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=cc.cluster_id AND org_id=$1)) AND ($7='' OR $7='kubernetes')
 UNION ALL
 SELECT 'host:'||h.id||':'||check_entry.ordinality,'node','host_cis',COALESCE(rule.internal_id,''),'cis-linux-2.0',COALESCE(check_entry.item->>'id',''),
 COALESCE(NULLIF(btrim(check_entry.item->>'title'),''),check_entry.item->>'id',''),COALESCE(rule.severity,'medium'),
 CASE lower(btrim(check_entry.item->>'result')) WHEN 'pass' THEN 'pass' WHEN 'fail' THEN 'fail' WHEN 'skip' THEN 'not_applicable' WHEN 'skipped' THEN 'not_applicable' ELSE 'manual' END,
 'node',h.node,h.node,h.cluster_id,'',concat(btrim(COALESCE(check_entry.item->>'detail','')),CASE WHEN COALESCE(h.profile,'')<>'' THEN concat(CASE WHEN btrim(COALESCE(check_entry.item->>'detail',''))<>'' THEN '; ' ELSE '' END,'profile=',h.profile) ELSE '' END),
 COALESCE(rule.remediation,'Review the host CIS detail and remediate according to the selected benchmark profile.'),h.observed_at,'{}'::jsonb,true
 FROM host_cis h CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(h.payload->'checks')='array' THEN h.payload->'checks' ELSE '[]'::jsonb END) WITH ORDINALITY check_entry(item,ordinality)
 LEFT JOIN host_rules rule ON rule.control_id=check_entry.item->>'id'
 WHERE h.org_id=$1 AND ($2::uuid IS NULL OR h.cluster_id=$2) AND ($7='' OR $7='node')
 AND (h.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=h.cluster_id AND org_id=$1))
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(h.payload->'checks')='array' THEN h.payload->'checks' ELSE '[]'::jsonb END) x WHERE jsonb_typeof(x) NOT IN ('object','null') OR EXISTS(SELECT 1 FROM unnest(ARRAY['id','title','result','detail']) field WHERE COALESCE(jsonb_typeof(x->field),'null') NOT IN ('string','null')))
 UNION ALL
 SELECT 'deployment:'||d.id||':vulnerability','workload','deployments','workload.high-critical-vulnerabilities','cis-k8s-1.9','','Workload has no unresolved high or critical findings',
 CASE WHEN d.critical_count>0 THEN 'critical' WHEN d.high_count>0 THEN 'high' WHEN d.finding_count>0 THEN 'medium' ELSE 'info' END,
 CASE WHEN d.critical_count>0 OR d.high_count>0 THEN 'fail' ELSE 'pass' END,d.kind,d.namespace||'/'||d.name,d.namespace||'/'||d.name,d.cluster_id,d.namespace,
 concat('risk_score=',d.risk_score,' total_findings=',d.finding_count,' critical=',d.critical_count,' high=',d.high_count),
 'Resolve or explicitly accept high and critical findings before treating the workload as compliant.',COALESCE(a.updated_at,s.updated_at,d.last_seen_at),'{}'::jsonb,true
 FROM deployments d LEFT JOIN network_policy_lifecycle_states s ON s.org_id=d.org_id AND s.cluster_id IS NOT DISTINCT FROM d.cluster_id AND s.workload=d.namespace||'/'||d.name
 LEFT JOIN LATERAL(SELECT updated_at FROM network_policy_apply_status a WHERE a.org_id=d.org_id AND a.cluster_id IS NOT DISTINCT FROM d.cluster_id AND a.workload=d.namespace||'/'||d.name ORDER BY updated_at DESC, flavor ASC LIMIT 1) a ON true
 WHERE d.org_id=$1 AND ($2::uuid IS NULL OR d.cluster_id=$2) AND ($3='' OR d.namespace=$3) AND ($7='' OR $7='workload')
 AND (d.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=d.cluster_id AND org_id=$1)) AND ($6::text[] IS NULL OR (d.namespace||'/'||d.name)=ANY($6))
 UNION ALL
 SELECT 'deployment:'||d.id||':policy','workload','network_policy_lifecycle','workload.network-policy-enforced','cis-k8s-1.9','','Workload traffic is governed by an applied network policy','high',
 CASE WHEN s.current_mode='protect' AND s.approval_status='applied' AND a.status='ok' THEN 'pass' WHEN s.current_mode='protect' AND s.approval_status='applied' THEN 'manual' ELSE 'fail' END,
 d.kind,d.namespace||'/'||d.name,d.namespace||'/'||d.name,d.cluster_id,d.namespace,
 concat('mode=',COALESCE(NULLIF(btrim(s.current_mode),''),'unset'),' approval_status=',COALESCE(NULLIF(btrim(s.approval_status),''),'unset'),' applier_status=',COALESCE(NULLIF(btrim(a.status),''),'missing'),CASE WHEN COALESCE(a.flavor,'')<>'' THEN ' flavor='||a.flavor ELSE '' END,CASE WHEN COALESCE(a.last_action,'')<>'' THEN ' last_action='||a.last_action ELSE '' END,CASE WHEN COALESCE(a.resource_ref,'')<>'' THEN ' resource='||a.resource_ref ELSE '' END,CASE WHEN COALESCE(a.error,'')<>'' THEN ' error='||a.error ELSE '' END),
 'Approve and apply the learned network policy, then confirm the live applier reports status=ok.',COALESCE(a.updated_at,s.updated_at,d.last_seen_at),'{}'::jsonb,true
 FROM deployments d LEFT JOIN network_policy_lifecycle_states s ON s.org_id=d.org_id AND s.cluster_id IS NOT DISTINCT FROM d.cluster_id AND s.workload=d.namespace||'/'||d.name
 LEFT JOIN LATERAL(SELECT flavor,last_action,status,resource_ref,error,updated_at FROM network_policy_apply_status a WHERE a.org_id=d.org_id AND a.cluster_id IS NOT DISTINCT FROM d.cluster_id AND a.workload=d.namespace||'/'||d.name ORDER BY updated_at DESC, flavor ASC LIMIT 1) a ON true
 WHERE d.org_id=$1 AND ($2::uuid IS NULL OR d.cluster_id=$2) AND ($3='' OR d.namespace=$3) AND ($7='' OR $7='workload')
 AND (d.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=d.cluster_id AND org_id=$1)) AND ($6::text[] IS NULL OR (d.namespace||'/'||d.name)=ANY($6))
 UNION ALL
 SELECT 'image-link:'||a.source_id||':secret','workload','image_scan_artifacts','container.image-secrets-absent','cis-k8s-1.9','','Images contain no embedded secret findings',
 CASE WHEN a.result_id IS NOT NULL AND a.secret_count>=0 AND lower(btrim(a.secret_status)) IN ('','observed') THEN CASE WHEN a.secret_count>0 THEN 'high' ELSE 'info' END ELSE 'medium' END,
 CASE WHEN a.result_id IS NOT NULL AND a.secret_count>=0 AND lower(btrim(a.secret_status)) IN ('','observed') THEN CASE WHEN a.secret_count>0 THEN 'fail' ELSE 'pass' END ELSE 'manual' END,
 a.kind||'/image',a.namespace||'/'||a.name||CASE WHEN btrim(COALESCE(NULLIF(btrim(a.image_digest),''),a.image_ref,''))<>'' THEN ' '||btrim(COALESCE(NULLIF(btrim(a.image_digest),''),a.image_ref,'')) ELSE '' END,a.owner_target,a.cluster_id,a.namespace,
 concat('image_ref=',a.image_ref,CASE WHEN a.image_digest<>'' THEN ' image_digest='||a.image_digest ELSE '' END,CASE WHEN a.result_id IS NOT NULL THEN ' image_scan_result_id='||a.result_id ELSE '' END,
 CASE WHEN a.result_id IS NULL THEN ' secret_scan=missing image_scan_result=missing' WHEN a.secret_count<0 THEN ' secret_scan=missing' WHEN lower(btrim(a.secret_status)) NOT IN ('','observed') THEN concat(' secret_scan_status=',lower(btrim(a.secret_status)),' secret_count=',a.secret_count) ELSE concat(' secret_scan_status=observed secret_count=',a.secret_count) END),
 'Remove embedded secrets from the image, rotate exposed credentials, rebuild, and rescan the image.',a.observed_at,'{}'::jsonb,true FROM artifact_input a WHERE ($7='' OR $7='workload')
 UNION ALL
 SELECT 'image-link:'||a.source_id||':file','workload','image_scan_artifacts','container.image-file-risks-absent','cis-k8s-1.9','','Images contain no risky filesystem metadata',
 CASE WHEN a.result_id IS NOT NULL AND a.file_risk_count>=0 AND lower(btrim(a.file_risk_status)) IN ('','observed') THEN CASE WHEN a.file_risk_count=0 THEN 'info' ELSE CASE a.severity_rank WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium' WHEN 2 THEN 'low' WHEN 1 THEN 'info' ELSE 'high' END END ELSE 'medium' END,
 CASE WHEN a.result_id IS NOT NULL AND a.file_risk_count>=0 AND lower(btrim(a.file_risk_status)) IN ('','observed') THEN CASE WHEN a.file_risk_count>0 THEN 'fail' ELSE 'pass' END ELSE 'manual' END,
 a.kind||'/image',a.namespace||'/'||a.name||CASE WHEN btrim(COALESCE(NULLIF(btrim(a.image_digest),''),a.image_ref,''))<>'' THEN ' '||btrim(COALESCE(NULLIF(btrim(a.image_digest),''),a.image_ref,'')) ELSE '' END,a.owner_target,a.cluster_id,a.namespace,
 concat('image_ref=',a.image_ref,CASE WHEN a.image_digest<>'' THEN ' image_digest='||a.image_digest ELSE '' END,CASE WHEN a.result_id IS NOT NULL THEN ' image_scan_result_id='||a.result_id ELSE '' END,
 CASE WHEN a.result_id IS NULL THEN ' file_risk_scan=missing image_scan_result=missing' WHEN a.file_risk_count<0 THEN ' file_risk_scan=missing' WHEN lower(btrim(a.file_risk_status)) NOT IN ('','observed') THEN concat(' file_risk_status=',lower(btrim(a.file_risk_status)),' file_risk_count=',a.file_risk_count) ELSE concat(' file_risk_status=observed file_risk_count=',a.file_risk_count,CASE WHEN a.file_risk_count>0 THEN CASE WHEN a.risk_types<>'' THEN ' risk_types='||a.risk_types ELSE '' END ELSE '' END) END),
 'Remove setuid/setgid binaries, world-writable sensitive paths, device nodes, and other risky filesystem metadata from the image, then rebuild and rescan.',a.observed_at,'{}'::jsonb,true FROM artifact_input a WHERE ($7='' OR $7='workload')
 UNION ALL
 SELECT 'cloud-summary:'||$1::text||':'||COALESCE($2::text,'organization'),'cloud','cloud_posture','cloud.posture.open-findings','cis-k8s-1.9','','Cloud resource posture findings are remediated','high',
 CASE WHEN counts.observed=0 THEN 'not_applicable' WHEN counts.open_findings>0 THEN 'fail' ELSE 'pass' END,'cloud','cloud-resources','cloud-resources',NULL::uuid,'',
 concat('resources_observed=',counts.observed,' resources_assessed=',counts.assessed,' open_findings=',counts.open_findings),'Enable cloud connector assessment and remediate open cloud-config findings.',COALESCE(counts.last_assessment,NOW()),'{}'::jsonb,true
 FROM (SELECT COUNT(DISTINCT a.id) FILTER(WHERE a.kind='cloud-resource') AS observed,COUNT(DISTINCT a.id) FILTER(WHERE a.kind='cloud-resource' AND f.id IS NOT NULL) AS assessed,COUNT(f.id) FILTER(WHERE f.kind='cloud-config' AND f.lifecycle='open') AS open_findings,MAX(f.last_seen_at) FILTER(WHERE f.kind='cloud-config') AS last_assessment FROM assets a LEFT JOIN findings f ON f.org_id=a.org_id AND f.asset_id=a.id AND f.kind='cloud-config' WHERE a.org_id=$1 AND ($2::uuid IS NULL OR a.cluster_id=$2) AND (a.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=a.cluster_id AND org_id=$1))) counts WHERE ($7='' OR $7='cloud')
 UNION ALL
 SELECT 'cloud-finding:'||f.id||':'||extract(epoch from f.first_seen_at)::text,'cloud','cloud_config_findings','cloud.posture.open-findings','cis-k8s-1.9','','Cloud resource posture findings are remediated',f.severity,'fail','cloud-resource',a.name,a.name,a.cluster_id,'',
 concat(CASE WHEN COALESCE(f.external_id,'')<>'' THEN f.external_id||': ' ELSE '' END,f.title,CASE WHEN COALESCE(f.description,'')<>'' THEN ' - '||f.description ELSE '' END),'Remediate the cloud-config finding or document a time-bound exemption.',f.last_seen_at,'{}'::jsonb,true
 FROM findings f JOIN assets a ON a.id=f.asset_id AND a.org_id=f.org_id WHERE f.org_id=$1 AND f.kind='cloud-config' AND f.lifecycle='open' AND ($2::uuid IS NULL OR a.cluster_id=$2) AND ($7='' OR $7='cloud') AND (a.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=a.cluster_id AND org_id=$1))
), expanded AS (
 SELECT r.source_id,r.scope,r.source,r.internal_id,COALESCE(m.framework,r.default_framework) AS framework,COALESCE(m.control_id,NULLIF(r.default_control,''),r.internal_id) AS control_id,
 CASE WHEN r.title='' THEN COALESCE(m.title,'') ELSE r.title END AS title,
 CASE WHEN r.mapped THEN COALESCE(NULLIF(lower(btrim(r.severity)),''),m.severity,'medium') ELSE r.severity END AS severity,
 r.status,r.target_kind,r.target,r.owner_target,r.cluster_id,r.namespace,r.evidence,r.remediation,r.observed_at,COALESCE(m.tags,r.tags) AS tags
 FROM raw_rows r LEFT JOIN mappings m ON r.mapped AND m.internal_id=r.internal_id
 WHERE ($6::text[] IS NULL OR r.owner_target=ANY($6))
), effective AS (
 SELECT substring(encode(digest(jsonb_build_array(source_id,framework,control_id)::text,'sha256'),'hex'),1,24) AS id,
 e.scope,e.source,e.internal_id,e.framework,e.control_id,e.title,e.severity,e.status,
 CASE WHEN e.status='fail' AND ex.id IS NOT NULL THEN 'exempted' ELSE e.status END AS effective_status,
 e.target_kind,e.target,e.cluster_id,e.namespace,e.evidence,e.remediation,e.observed_at,e.tags,
 CASE WHEN e.status='fail' AND ex.id IS NOT NULL THEN jsonb_build_object('id',ex.id,'reason',ex.reason,'expires_at',ex.expires_at) ELSE NULL END AS exemption
 FROM expanded e LEFT JOIN LATERAL (
 SELECT ce.id,ce.reason,ce.expires_at FROM compliance_exemptions ce WHERE ce.org_id=$1 AND ce.framework=e.framework AND ce.control_id=e.control_id AND ce.revoked_at IS NULL AND ce.expires_at>NOW()
 AND (ce.cluster_id IS NULL OR (ce.cluster_id=e.cluster_id AND EXISTS(SELECT 1 FROM clusters WHERE id=ce.cluster_id AND org_id=$1)))
 ORDER BY (ce.cluster_id IS NULL),ce.created_at DESC,ce.id DESC LIMIT 1
 ) ex ON true
), matching AS MATERIALIZED (
 SELECT * FROM effective WHERE ($8='' OR framework=$8) AND ($9='' OR control_id=$9) AND ($10='' OR CASE WHEN effective_status IN ('pass','fail','exempted','not_applicable') THEN effective_status ELSE 'manual' END=$10)
 AND ($11='' OR strpos(lower(concat_ws(' ',scope,source,framework,control_id,title,target,evidence)),lower($11))>0)
 AND ($12='' OR target=$12)
)
`

const evidenceItemJSON = `jsonb_build_object('id',id,'scope',scope,'source',source,'internal_id',internal_id,'framework',framework,'control_id',control_id,'title',title,'severity',severity,'status',status,'effective_status',effective_status,'target_kind',target_kind,'target',target,'cluster_id',cluster_id,'namespace',namespace,'evidence',evidence,'remediation',remediation,'observed_at',observed_at,'tags_v2',tags,'exemption',exemption)`
