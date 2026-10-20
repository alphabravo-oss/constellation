import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { aliasCluster, aliasSibling, declaredAliases, deepAliases, installAliasFixture, type AliasCase } from "./fixtures/canonical-aliases";
const query="context=alias-proof&tag=first&tag=second&literal=%25_needle%2Fexact";
async function canonical(page:Page,item:AliasCase,input=query){
 await page.goto(`${item.from}?${input}#evidence`);
 const expected=new URLSearchParams(input);for(const[key,value]of Object.entries(item.defaults??{}))expected.set(key,value);
 await expect.poll(()=>new URL(page.url()).pathname,item.contract).toBe(item.to);
 await expect.poll(()=>new URL(page.url()).hash,item.contract).toBe("#evidence");
 await expect.poll(()=>{const actual=new URL(page.url()).searchParams;return [...new Set([...expected.keys()])].every(key=>JSON.stringify(actual.getAll(key))===JSON.stringify(expected.getAll(key)));},item.contract).toBe(true);
 if(item.to==="/auth/login")await expect(page.getByRole("heading",{name:"Sign in to Constellation",exact:true})).toBeVisible();
 else{await page.waitForFunction(()=>{const main=document.querySelector("main");return !!main?.textContent?.trim()&&!/^Loading(?:…|\.)?$/.test(main.textContent.trim());});await expect(page.getByRole("heading",{name:"Page not found",exact:true})).not.toBeVisible();await expect(page.getByRole("heading",{name:/This page could not be loaded|Unable to load this page/i})).not.toBeVisible();}
 const url=new URL(page.url());expect(url.searchParams.getAll("tag")).toEqual(["first","second"]);expect(url.searchParams.get("literal")).toBe("%_needle/exact");
}

test("the finite browser matrix covers every declared alias mapping",async()=>{
 const source=await readFile(new URL("../src/app-router.tsx",import.meta.url),"utf8");const registered=source.split("\n").filter(line=>line.includes("const ")&&(line.includes("beforeLoad: aliasRedirect")||line.includes("LegacyClusterRedirect />"))).map(line=>{const parent=line.match(/getParentRoute:\s*\(\)\s*=>\s*(\w+)/)?.[1],path=line.match(/path:\s*"([^"]+)"/)?.[1];expect(parent,line).toBeTruthy();expect(path,line).toBeTruthy();return`${parent}:${path}`;});expect(registered).toHaveLength(96);expect(new Set(declaredAliases.map(row=>row.contract))).toEqual(new Set(registered));expect(declaredAliases).toHaveLength(96);
});
for(let start=0;start<declaredAliases.length;start+=8){const batch=declaredAliases.slice(start,start+8);test(`canonical alias mappings ${start+1}–${start+batch.length}`,async({page})=>{test.setTimeout(90000);await installAliasFixture(page);for(const item of batch)await test.step(item.contract,async()=>canonical(page,item));});}
for(let start=0;start<deepAliases.length;start+=8){const batch=deepAliases.slice(start,start+8);test(`valid detail/form alias suffixes ${start+1}–${start+batch.length}`,async({page})=>{test.setTimeout(90000);await installAliasFixture(page);for(const item of batch)await test.step(item.contract,async()=>canonical(page,item));});}

test("forced component roles and incident tab override conflicting bookmark defaults without losing repeated filters",async({page})=>{
 await installAliasFixture(page);for(const[path,role]of [["controllers","controller"],["enforcers","enforcer"],["agents","enforcer"],["scanners","scanner"]])await canonical(page,{contract:path,from:`/clusters/${aliasSibling}/${path}`,to:`/clusters/${aliasSibling}/components`,defaults:{role}},`${query}&role=spoof&role=second`);
 await canonical(page,{contract:"incident default",from:`/clusters/${aliasSibling}/incidents`,to:`/clusters/${aliasSibling}/timeline`,defaults:{tab:"incident"}},`${query}&tab=activity&tab=event`);
});

test("an alias soft transition replaces its history entry and Back/Forward retain explicit sibling scope",async({page})=>{
 await installAliasFixture(page);await page.goto(`/clusters/${aliasCluster}/neuvector?context=origin#origin`);await expect(page.getByTestId("neuvector-switchboard")).toBeVisible();
 // Use the installed router's public navigation method to exercise an actual
 // soft transition, then prove the same document survived the redirect.
 await page.evaluate(async href=>{const runtime=window as typeof window & { __TSR_ROUTER__: {navigate:(options:{href:string})=>Promise<void>}; aliasDocumentProof?:string };runtime.aliasDocumentProof="same-document";await runtime.__TSR_ROUTER__.navigate({href});},`/clusters/${aliasSibling}/controllers?${query}#evidence`);
 expect(await page.evaluate(()=>(window as typeof window & {aliasDocumentProof?:string}).aliasDocumentProof)).toBe("same-document");
 await expect.poll(()=>new URL(page.url()).pathname).toBe(`/clusters/${aliasSibling}/components`);await expect(page.getByRole("heading",{name:"Components",exact:true})).toBeVisible();expect(new URL(page.url()).searchParams.get("role")).toBe("controller");await page.goBack();await expect(page).toHaveURL(`/clusters/${aliasCluster}/neuvector?context=origin#origin`);await page.goForward();await expect.poll(()=>new URL(page.url()).pathname).toBe(`/clusters/${aliasSibling}/components`);expect(new URL(page.url()).searchParams.getAll("tag")).toEqual(["first","second"]);expect(new URL(page.url()).hash).toBe("#evidence");
 await page.evaluate(async href=>{await(window as typeof window & {__TSR_ROUTER__:{navigate:(options:{href:string})=>Promise<void>}}).__TSR_ROUTER__.navigate({href});},`/hosts/00000000-0000-4000-8000-000000000001?${query}#evidence`);
 await expect.poll(()=>new URL(page.url()).pathname).toBe(`/clusters/${aliasCluster}/nodes/00000000-0000-4000-8000-000000000001`);expect(await page.evaluate(()=>(window as typeof window & {aliasDocumentProof?:string}).aliasDocumentProof)).toBe("same-document");
 await page.goBack();await expect.poll(()=>new URL(page.url()).pathname).toBe(`/clusters/${aliasSibling}/components`);expect(new URL(page.url()).searchParams.get("role")).toBe("controller");await page.goForward();await expect.poll(()=>new URL(page.url()).pathname).toBe(`/clusters/${aliasCluster}/nodes/00000000-0000-4000-8000-000000000001`);expect(new URL(page.url()).searchParams.getAll("tag")).toEqual(["first","second"]);
});

test("organization audit and CVE detail retain their legitimate organization/cluster routes",async({page})=>{
 await installAliasFixture(page);for(const path of ["/organization/audit",`/clusters/${aliasSibling}/audit`,"/cve/CVE-2026-12345",`/clusters/${aliasSibling}/cve/CVE-2026-12345`]){await page.goto(`${path}?${query}#evidence`);await expect.poll(()=>new URL(page.url()).pathname).toBe(path);await expect(page.getByRole("heading",{name:"Page not found",exact:true})).not.toBeVisible();expect(new URL(page.url()).searchParams.getAll("tag")).toEqual(["first","second"]);expect(new URL(page.url()).hash).toBe("#evidence");}
});

test("legacy entry with no registered clusters returns to the canonical picker without querying domain inventories",async({page})=>{
 const requests=await installAliasFixture(page,{empty:true});await page.goto(`/hosts?${query}#evidence`);await expect(page).toHaveURL("/clusters");await expect(page.getByRole("heading",{name:"Clusters",exact:true})).toBeVisible();expect(requests.some(url=>url.pathname.endsWith("/nodes"))).toBe(false);
});
