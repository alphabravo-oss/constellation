package handler

// assetDisplayNameSQL uses only metadata attached to this asset. Keep the raw
// asset name and digest unchanged; display identity also drives sorting and CSV.
// References with @digest retain the named portion. Never invent a latest tag.
const assetDisplayNameSQL = `CASE WHEN a.kind <> 'image' THEN a.name ELSE COALESCE(
 NULLIF(CASE WHEN split_part(btrim(a.labels->>'image_ref_normalized'),'@',1) !~* '^(sha(256|384|512):|[a-f0-9]{64}$)' THEN split_part(btrim(a.labels->>'image_ref_normalized'),'@',1) END,''),
 NULLIF(CASE WHEN split_part(btrim(a.labels->>'image_ref'),'@',1) !~* '^(sha(256|384|512):|[a-f0-9]{64}$)' THEN split_part(btrim(a.labels->>'image_ref'),'@',1) END,''),
 CASE WHEN COALESCE(NULLIF(i.repository,''),NULLIF(a.labels->>'image_repository','')) IS NOT NULL THEN
   CASE WHEN COALESCE(i.registry,'') <> ''
      AND COALESCE(NULLIF(i.repository,''),a.labels->>'image_repository') NOT LIKE i.registry||'/%'
      AND COALESCE(NULLIF(i.repository,''),a.labels->>'image_repository') !~ '^([^/]*[.:][^/]*|localhost)/'
   THEN rtrim(i.registry,'/')||'/' ELSE '' END
   || split_part(COALESCE(NULLIF(i.repository,''),a.labels->>'image_repository'),'@',1)
   || CASE WHEN split_part(COALESCE(NULLIF(i.repository,''),a.labels->>'image_repository'),'@',1) !~ ':[^/]*$'
      AND COALESCE(NULLIF(i.tag,''),NULLIF(a.labels->>'image_tag','')) IS NOT NULL
   THEN ':'||COALESCE(NULLIF(i.tag,''),a.labels->>'image_tag') ELSE '' END END,
 NULLIF(CASE WHEN split_part(btrim(a.name),'@',1) !~* '^(sha(256|384|512):|[a-f0-9]{64}$)' THEN split_part(btrim(a.name),'@',1) END,''),
 'Unnamed image') END`
