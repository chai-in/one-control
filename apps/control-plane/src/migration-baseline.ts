import { createHash } from "node:crypto";
import type { TransactionQuery } from "./database.js";
import { frozenV1Catalogs } from "./frozen-v1.js";

export type FrozenV1Engine = "postgres-18.6" | "pglite-0.5.9";
export type FrozenV1Admission =
  | { readonly kind: "empty" }
  | { readonly kind: "compatible"; readonly admission: "catalog-v1"; readonly catalogSha256: string }
  | { readonly kind: "incompatible"; readonly reason: "boundary" | "catalog" | "marker" };

const catalogSql = `SELECT CASE WHEN pg_catalog.octet_length(q.descriptor) OPERATOR(pg_catalog.<=) 131072
  THEN q.descriptor ELSE NULL END AS descriptor FROM (SELECT pg_catalog.left(pg_catalog.jsonb_build_object(
 'relations', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,
     c.relispartition,c.relreplident,c.reloptions,a.amname,c.reloftype<>0 AS typed
   FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_am a ON a.oid=c.relam
   WHERE c.relnamespace=$1::pg_catalog.oid ORDER BY c.relname LIMIT 129) r),
 'columns', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT c.relname,a.attname,a.attnum,pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,
     tn.nspname AS type_schema,t.typname,a.attnotnull,a.attidentity,a.attgenerated,a.attisdropped,
     a.atthasmissing,a.attoptions,a.attfdwoptions,a.attislocal,a.attinhcount,
     pg_catalog.left(pg_catalog.pg_get_expr(d.adbin,d.adrelid),8193) AS default_expr,
     cn.nspname AS collation_schema,co.collname AS collation
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
   LEFT JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
   LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
   LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
   LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
   LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
   WHERE c.relnamespace=$1::pg_catalog.oid AND c.relkind NOT IN ('i','I') AND a.attnum>0
   ORDER BY c.relname,a.attnum LIMIT 129) r),
 'constraints', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT c.relname,k.conname,k.contype,k.condeferrable,k.condeferred,k.convalidated,k.conenforced,
     k.connoinherit,k.conislocal,k.coninhcount,
     pg_catalog.left(pg_catalog.pg_get_constraintdef(k.oid,false),8193) AS definition
   FROM pg_catalog.pg_constraint k LEFT JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
   WHERE k.connamespace=$1::pg_catalog.oid ORDER BY c.relname,k.conname LIMIT 129) r),
 'indexes', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT t.relname,i.relname AS index_name,x.indisunique,x.indisprimary,x.indisvalid,
     x.indisready,x.indislive,x.indisclustered,x.indisreplident,x.indnatts,x.indnkeyatts,
     x.indnullsnotdistinct,x.indkey::pg_catalog.text,x.indoption::pg_catalog.text,
     pg_catalog.left(pg_catalog.pg_get_expr(x.indpred,x.indrelid),8193) AS predicate,
     pg_catalog.left(pg_catalog.pg_get_expr(x.indexprs,x.indrelid),8193) AS expressions,
     (SELECT pg_catalog.jsonb_agg(pg_catalog.left(pg_catalog.pg_get_indexdef(x.indexrelid,n,false),8193) ORDER BY n)
       FROM pg_catalog.generate_series(1,x.indnatts) n) AS keys,
     (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(n.nspname,o.opcname) ORDER BY v.ordinality)
       FROM pg_catalog.unnest(x.indclass) WITH ORDINALITY v(oid,ordinality)
       JOIN pg_catalog.pg_opclass o ON o.oid=v.oid JOIN pg_catalog.pg_namespace n ON n.oid=o.opcnamespace) AS opclasses,
     (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(n.nspname,c.collname) ORDER BY v.ordinality)
       FROM pg_catalog.unnest(x.indcollation) WITH ORDINALITY v(oid,ordinality)
       LEFT JOIN pg_catalog.pg_collation c ON c.oid=v.oid LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace) AS collations
   FROM pg_catalog.pg_index x JOIN pg_catalog.pg_class t ON t.oid=x.indrelid
   JOIN pg_catalog.pg_class i ON i.oid=x.indexrelid
   WHERE t.relnamespace=$1::pg_catalog.oid ORDER BY t.relname,i.relname LIMIT 129) r),
 'sequences', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT s.relname,q.seqtypid::pg_catalog.regtype::pg_catalog.text AS type,q.seqstart::pg_catalog.text,
     q.seqincrement::pg_catalog.text,q.seqmax::pg_catalog.text,q.seqmin::pg_catalog.text,q.seqcache::pg_catalog.text,q.seqcycle,
     t.relname AS owned_table,a.attname AS owned_column,d.deptype
   FROM pg_catalog.pg_class s JOIN pg_catalog.pg_sequence q ON q.seqrelid=s.oid
   LEFT JOIN pg_catalog.pg_depend d ON d.classid='pg_catalog.pg_class'::pg_catalog.regclass
     AND d.objid=s.oid AND d.refclassid='pg_catalog.pg_class'::pg_catalog.regclass AND d.deptype IN ('a','i')
   LEFT JOIN pg_catalog.pg_class t ON t.oid=d.refobjid
   LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid
   WHERE s.relnamespace=$1::pg_catalog.oid ORDER BY s.relname LIMIT 129) r),
 'types', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT t.typname,t.typtype,t.typcategory,c.relname,e.typname AS element,
     CASE WHEN en.oid=$1::pg_catalog.oid THEN '$managed' ELSE en.nspname END AS element_schema,t.typnotnull,t.typdefault
   FROM pg_catalog.pg_type t LEFT JOIN pg_catalog.pg_class c ON c.oid=t.typrelid
   LEFT JOIN pg_catalog.pg_type e ON e.oid=t.typelem
   LEFT JOIN pg_catalog.pg_namespace en ON en.oid=e.typnamespace
   WHERE t.typnamespace=$1::pg_catalog.oid ORDER BY t.typname LIMIT 129) r),
 'triggers', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT c.relname,k.conname,p.proname,n.nspname,g.tgtype,g.tgenabled,g.tgisinternal,
     g.tgdeferrable,g.tginitdeferred,g.tgnargs,g.tgattr::pg_catalog.text,g.tgqual IS NOT NULL AS qualified,
     g.tgoldtable,g.tgnewtable
   FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid=g.tgrelid
   LEFT JOIN pg_catalog.pg_constraint k ON k.oid=g.tgconstraint
   JOIN pg_catalog.pg_proc p ON p.oid=g.tgfoid JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE c.relnamespace=$1::pg_catalog.oid ORDER BY c.relname,k.conname,p.proname,g.tgtype LIMIT 129) r),
 'unexpected', (SELECT coalesce(pg_catalog.jsonb_agg(r),'[]'::pg_catalog.jsonb) FROM (
   SELECT 'routine' AS kind,p.proname AS name FROM pg_catalog.pg_proc p WHERE p.pronamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'trigger',g.tgname FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid=g.tgrelid WHERE c.relnamespace=$1::pg_catalog.oid AND NOT g.tgisinternal
   UNION ALL SELECT 'policy',p.polname FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid WHERE c.relnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'rule',r.rulename FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class WHERE c.relnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'extension',e.extname FROM pg_catalog.pg_extension e WHERE e.extnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'collation',c.collname FROM pg_catalog.pg_collation c WHERE c.collnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'conversion',c.conname FROM pg_catalog.pg_conversion c WHERE c.connamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'operator',o.oprname FROM pg_catalog.pg_operator o WHERE o.oprnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'opclass',o.opcname FROM pg_catalog.pg_opclass o WHERE o.opcnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'opfamily',o.opfname FROM pg_catalog.pg_opfamily o WHERE o.opfnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'statistics',s.stxname FROM pg_catalog.pg_statistic_ext s WHERE s.stxnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'text-search-config',c.cfgname FROM pg_catalog.pg_ts_config c WHERE c.cfgnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'text-search-dict',d.dictname FROM pg_catalog.pg_ts_dict d WHERE d.dictnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'text-search-parser',p.prsname FROM pg_catalog.pg_ts_parser p WHERE p.prsnamespace=$1::pg_catalog.oid
   UNION ALL SELECT 'text-search-template',t.tmplname FROM pg_catalog.pg_ts_template t WHERE t.tmplnamespace=$1::pg_catalog.oid
   ORDER BY kind,name LIMIT 129) r)
)::pg_catalog.text,131073) AS descriptor) q`;

export async function inspectFrozenV1(
  tx: TransactionQuery,
  boundary: { readonly engine: FrozenV1Engine; readonly namespace: string },
): Promise<FrozenV1Admission> {
  if (
    typeof boundary.namespace !== "string" ||
    boundary.namespace.includes("\0") ||
    Buffer.byteLength(boundary.namespace) < 1 ||
    Buffer.byteLength(boundary.namespace) > 63
  )
    return { kind: "incompatible", reason: "boundary" };
  const [identity] = await tx.query(`SELECT pg_catalog.current_schema() AS namespace,
    pg_catalog.current_schemas(false)::pg_catalog.text[] AS path,
    pg_catalog.current_setting('server_version_num') AS version,
    pg_catalog.to_regnamespace(pg_catalog.current_schema())::pg_catalog.oid::pg_catalog.text AS oid`);
  if (
    !Object.hasOwn(frozenV1Catalogs, boundary.engine) ||
    identity?.namespace !== boundary.namespace ||
    identity.version !== "180006" ||
    JSON.stringify(identity.path) !== JSON.stringify([boundary.namespace, "pg_catalog"]) ||
    typeof identity.oid !== "string" ||
    !/^[1-9][0-9]{0,9}$/.test(identity.oid)
  )
    return { kind: "incompatible", reason: "boundary" };
  const [preflight] = await tx.query(
    `SELECT
    EXISTS (SELECT 1 FROM pg_catalog.pg_type t
      LEFT JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) t.typrelid
      LEFT JOIN pg_catalog.pg_type e ON e.oid OPERATOR(pg_catalog.=) t.typelem
      LEFT JOIN pg_catalog.pg_class ec ON ec.oid OPERATOR(pg_catalog.=) e.typrelid
      WHERE t.typnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid AND NOT
        ((t.typtype OPERATOR(pg_catalog.=) 'c' AND c.relkind OPERATOR(pg_catalog.=) 'r' AND c.reloftype OPERATOR(pg_catalog.=) 0) OR
         (t.typcategory OPERATOR(pg_catalog.=) 'A' AND e.typnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid AND e.typtype OPERATOR(pg_catalog.=) 'c' AND ec.relkind OPERATOR(pg_catalog.=) 'r')))
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_operator WHERE oprnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid)
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc WHERE pronamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid)
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_inherits h JOIN pg_catalog.pg_class c
      ON c.oid OPERATOR(pg_catalog.=) h.inhrelid OR c.oid OPERATOR(pg_catalog.=) h.inhparent WHERE c.relnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid)
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid AND reloftype OPERATOR(pg_catalog.<>) 0)
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) a.attrelid
      JOIN pg_catalog.pg_type t ON t.oid OPERATOR(pg_catalog.=) a.atttypid
      WHERE c.relnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid AND a.attnum OPERATOR(pg_catalog.>) 0
        AND t.typnamespace OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.regnamespace)
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
      LEFT JOIN pg_catalog.pg_type t ON d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass AND t.oid OPERATOR(pg_catalog.=) d.refobjid
      LEFT JOIN pg_catalog.pg_proc p ON d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass AND p.oid OPERATOR(pg_catalog.=) d.refobjid
      LEFT JOIN pg_catalog.pg_operator o ON d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_operator'::pg_catalog.regclass AND o.oid OPERATOR(pg_catalog.=) d.refobjid
      LEFT JOIN pg_catalog.pg_class r ON d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass AND r.oid OPERATOR(pg_catalog.=) d.refobjid
      WHERE (d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_attrdef'::pg_catalog.regclass AND d.objid OPERATOR(pg_catalog.=) ANY
        (SELECT a.oid FROM pg_catalog.pg_attrdef a JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) a.adrelid WHERE c.relnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid)
        OR d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_constraint'::pg_catalog.regclass AND d.objid OPERATOR(pg_catalog.=) ANY
        (SELECT oid FROM pg_catalog.pg_constraint WHERE connamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid)
        OR d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass AND d.objid OPERATOR(pg_catalog.=) ANY
        (SELECT oid FROM pg_catalog.pg_class WHERE relnamespace OPERATOR(pg_catalog.=) $1::pg_catalog.oid))
        AND (t.typnamespace OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.regnamespace OR
          p.pronamespace OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.regnamespace OR o.oprnamespace OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.regnamespace OR r.relnamespace OPERATOR(pg_catalog.<>) $1::pg_catalog.oid))
    AS unsafe`,
    [identity.oid],
  );
  if (preflight?.unsafe !== false) return { kind: "incompatible", reason: "catalog" };
  const [row] = await tx.query(catalogSql, [identity.oid]);
  if (typeof row?.descriptor !== "string" || Buffer.byteLength(row.descriptor) > 131_072)
    return { kind: "incompatible", reason: "catalog" };
  const descriptor: unknown = JSON.parse(row.descriptor);
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor))
    return { kind: "incompatible", reason: "catalog" };
  const groups = Object.values(descriptor);
  if (groups.length !== 8 || groups.some((group) => !Array.isArray(group) || group.length > 128))
    return { kind: "incompatible", reason: "catalog" };
  if (groups.every((group) => group.length === 0)) return { kind: "empty" };
  if (row.descriptor !== frozenV1Catalogs[boundary.engine])
    return { kind: "incompatible", reason: "catalog" };
  const namespace = `"${boundary.namespace.replaceAll('"', '""')}"`;
  const marker = await tx.query(
    `SELECT version FROM ${namespace}.schema_migrations ORDER BY version LIMIT 3`,
  );
  if (marker.length !== 1 || marker[0]?.version !== 1) return { kind: "incompatible", reason: "marker" };
  return {
    kind: "compatible",
    admission: "catalog-v1",
    catalogSha256: createHash("sha256").update(row.descriptor).digest("hex"),
  };
}
