import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { LIVE_EMAIL, LIVE_PASSWORD } from "./env";
import { totp } from "./totp";

const configured=!!process.env.BUNDLED_IDENTITY_USERNAME;
async function sso(page:Page){
 await page.goto("/auth/login");
 await page.getByRole("button",{name:"Continue with SSO"}).click();
 await expect(page.locator("#u")).toBeVisible();
 expect(await page.locator("html").evaluate(e=>getComputedStyle(e).getPropertyValue("--accent").trim())).toBe("#0d9488");
 expect(await page.content()).not.toMatch(/zitadel/i);
 await page.screenshot({path:test.info().outputPath("bundled-teal-signin.png"),fullPage:true});
 await page.fill("#u",process.env.BUNDLED_IDENTITY_USERNAME!);await page.fill("#p",process.env.BUNDLED_IDENTITY_PASSWORD!);
 const combined=await page.locator("#login-code").count()>0;
 if(combined)await page.fill("#login-code",totp(process.env.BUNDLED_IDENTITY_TOTP_SECRET!));
 await page.locator('form[action="/signin/password"] button').click();
 if(!combined){await page.fill("#c",totp(process.env.BUNDLED_IDENTITY_TOTP_SECRET!));await page.locator('form[action="/signin/totp"] button').click();}
 await expect(page).toHaveURL(/\/clusters(?:[/?#]|$)/);
}

// Run after the local-account policy proofs: this test intentionally revokes
// normal local sessions, then restores the original policy using recovery.
test("bundled SSO, local-only and SSO-only policies work with independent recovery",async({browser,baseURL})=>{
 test.skip(!configured,"requires bundled identity proof credentials");test.setTimeout(360_000);
 const headers={Origin:baseURL!,"X-Constellation-Client":"browser"};
 const admin=await browser.newContext({baseURL,storageState:{cookies:[],origins:[]}});
 const user=await browser.newContext({baseURL,storageState:{cookies:[],origins:[]}});
 const recovery=await browser.newContext({baseURL,storageState:{cookies:[],origins:[]}});
 let original: {local:unknown;oidc:unknown}|undefined;
 let replicas:number|undefined;
 const deployment=process.env.BUNDLED_IDENTITY_DEPLOYMENT??"identity-engine";
 const namespace=process.env.BUNDLED_IDENTITY_NAMESPACE??"constellation-system";
 try{
  // The preceding negative proof exhausts the real shared IP limiter. Honor it.
  for(;;){
   const response=await admin.request.post("/api/v1/auth/local",{headers,data:{email:LIVE_EMAIL,password:LIVE_PASSWORD,totp:totp(process.env.LIVE_TOTP_SECRET!)}});
   if(response.ok())break;
   expect(response.status()).toBe(429);
   await new Promise(resolve=>setTimeout(resolve,Number(response.headers()["retry-after"])*1000+200));
  }
  original=await(await admin.request.get("/api/v1/settings/identity")).json();
  const settings=await admin.newPage();await settings.goto("/settings/identity");
  await settings.getByLabel("Single sign-on",{exact:true}).click();await expect(settings.getByRole("option",{name:"Bundled single sign-on",exact:true})).toBeVisible();await settings.keyboard.press("Escape");
  const up=await user.newPage();await sso(up);
  const me=await(await user.request.get("/api/v1/auth/me")).json();expect(me.roles).toEqual(["SecurityAdmin"]);
  expect((await user.request.get("/api/v1/local-users")).status()).toBe(403);
  expect(JSON.stringify(await user.cookies())).not.toMatch(/zitadel/i);
  // Disable SSO through the actual settings form; the provisioned option stays.
  await settings.getByLabel("Single sign-on",{exact:true}).click();await settings.getByRole("option",{name:"Disabled",exact:true}).click();
  const saved=settings.waitForResponse(r=>r.url().endsWith("/api/v1/settings/identity")&&r.request().method()==="PUT");await settings.getByRole("button",{name:"Save sign-in methods"}).click();expect((await saved).status()).toBe(200);
  await expect.poll(async()=>(await(await admin.request.get("/api/v1/auth/providers")).json()).oidc).toBe(false);
  expect((await admin.request.get("/api/v1/auth/me")).status()).toBe(200);
  const methods=await recovery.newPage();await methods.goto("/auth/login");await expect(methods.getByRole("button",{name:"Continue with SSO"})).toHaveCount(0);await expect(methods.getByRole("textbox",{name:"Email",exact:true})).toBeVisible();
  const localOnly=await browser.newContext({baseURL,storageState:{cookies:[],origins:[]}});
  try{
   await new Promise(resolve=>setTimeout(resolve,30_100-Date.now()%30_000));
   expect((await localOnly.request.post("/api/v1/auth/local",{headers,data:{email:LIVE_EMAIL,password:LIVE_PASSWORD,totp:totp(process.env.LIVE_TOTP_SECRET!)}})).status()).toBe(200);
  }finally{await localOnly.request.post("/api/v1/auth/logout",{headers});await localOnly.close();}
  // Restore the bundled selection with the create-only secret still available.
  await settings.reload();await settings.getByLabel("Single sign-on",{exact:true}).click();await settings.getByRole("option",{name:"Bundled single sign-on",exact:true}).click();
  const restored=settings.waitForResponse(r=>r.url().endsWith("/api/v1/settings/identity")&&r.request().method()==="PUT");await settings.getByRole("button",{name:"Save sign-in methods"}).click();expect((await restored).status()).toBe(200);
  await expect.poll(async()=>(await(await admin.request.get("/api/v1/settings/identity")).json()).ready).toBe(true);
  // Local off keeps the existing SSO session and the SSO login choice.
  const current=await(await admin.request.get("/api/v1/settings/identity")).json();
  expect((await admin.request.put("/api/v1/settings/identity",{headers,data:{local:{...current.local,enabled:false},oidc:current.oidc,revision:current.revision}})).status()).toBe(200);
  expect((await recovery.request.post("/api/v1/auth/local",{headers,data:{email:LIVE_EMAIL,password:LIVE_PASSWORD,totp:totp(process.env.LIVE_TOTP_SECRET!)}})).status()).toBe(401);
  await methods.goto("/auth/login");await expect(methods.getByRole("textbox",{name:"Email",exact:true})).toHaveCount(0);await expect(methods.getByRole("button",{name:"Continue with SSO"})).toBeVisible();
  expect((await user.request.get("/api/v1/auth/me")).status()).toBe(200);
  await up.goto("/auth/login");await up.getByRole("button",{name:"Continue with SSO"}).click();await expect(up).toHaveURL(/\/clusters(?:[/?#]|$)/);
  expect((await(await user.request.get("/api/v1/auth/me")).json()).roles).toEqual(["SecurityAdmin"]);
  // First bearer verification happens after the issuer is completely down.
  const bearerContext=await browser.newContext({baseURL,storageState:await user.storageState()});
  let bearer:string;
  try{
   const verifier=randomBytes(32).toString("base64url");const callback=baseURL+"/api/v1/auth/oidc/callback";
   const authURL=new URL(baseURL+"/oauth/v2/authorize");authURL.search=new URLSearchParams({client_id:process.env.BUNDLED_IDENTITY_CLIENT_ID!,redirect_uri:callback,response_type:"code",scope:"openid email profile",nonce:randomBytes(24).toString("base64url"),state:"unbound-proof-flow",code_challenge:createHash("sha256").update(verifier).digest("base64url"),code_challenge_method:"S256"}).toString();
   const capture=await bearerContext.newPage();await capture.goto(authURL.toString());await expect(capture).toHaveURL(/\/api\/v1\/auth\/oidc\/callback\?/);
   const code=new URL(capture.url()).searchParams.get("code");expect(code).toBeTruthy();
   const tokens=await bearerContext.request.post("/oauth/v2/token",{headers:{Authorization:"Basic "+Buffer.from(encodeURIComponent(process.env.BUNDLED_IDENTITY_CLIENT_ID!)+":"+encodeURIComponent(process.env.BUNDLED_IDENTITY_CLIENT_SECRET!)).toString("base64")},form:{grant_type:"authorization_code",code:code!,redirect_uri:callback,code_verifier:verifier}});expect(tokens.ok()).toBeTruthy();
   const response=await tokens.json();bearer=response.access_token;
   for(const token of [response.id_token,bearer])expect(Buffer.from(token.split(".")[1],"base64url").toString()).not.toMatch(/zitadel/i);
  }finally{await bearerContext.close();}
  const fixture=JSON.parse(execFileSync("kubectl",["-n",namespace,"get","deployment",deployment,"-o","json"],{encoding:"utf8"}));replicas=fixture.spec.replicas;
  execFileSync("kubectl",["-n",namespace,"scale",`deployment/${deployment}`,"--replicas=0"]);
  const selector=Object.entries(fixture.spec.selector.matchLabels).map(([k,v])=>`${k}=${v}`).join(",");execFileSync("kubectl",["-n",namespace,"wait","--for=delete","pod","-l",selector,"--timeout=60s"]);
  expect((await user.request.get("/api/v1/auth/me")).status()).toBe(200);
  const unseen=await user.request.get("/api/v1/auth/me",{headers:{Authorization:`Bearer ${bearer!}`}});expect(unseen.status()).toBe(200);expect((await unseen.json()).roles).toEqual(["SecurityAdmin"]);
  const rp=await recovery.newPage();await rp.goto("/auth/login");await rp.getByRole("button",{name:"Emergency access",exact:true}).click();await rp.getByLabel("Password",{exact:true}).fill(process.env.BREAK_GLASS_PASSWORD!);await rp.getByLabel("Authenticator code").fill(totp(process.env.BREAK_GLASS_TOTP_SECRET!));await rp.getByRole("button",{name:"Sign in",exact:true}).click();await expect(rp).toHaveURL(/\/clusters(?:[/?#]|$)/);
  expect((await(await recovery.request.get("/api/v1/auth/me")).json()).email).toBe("break-glass@constellation.local");
  await rp.screenshot({path:test.info().outputPath("sso-only-recovery-engine-down.png"),fullPage:true});

 }finally{
  if(replicas!==undefined){execFileSync("kubectl",["-n",namespace,"scale",`deployment/${deployment}`,`--replicas=${replicas}`]);execFileSync("kubectl",["-n",namespace,"rollout","status",`deployment/${deployment}`,"--timeout=90s"]);}
  if(original){
   if(!(await recovery.request.get("/api/v1/settings/identity")).ok()){
    await new Promise(resolve=>setTimeout(resolve,30_100-Date.now()%30_000));
    await recovery.request.post("/api/v1/auth/break-glass",{headers,data:{password:process.env.BREAK_GLASS_PASSWORD!,totp:totp(process.env.BREAK_GLASS_TOTP_SECRET!)}});
   }
   const response=await recovery.request.get("/api/v1/settings/identity");if(response.ok()){const v=await response.json();expect((await recovery.request.put("/api/v1/settings/identity",{headers,data:{local:original.local,oidc:original.oidc,revision:v.revision}})).status()).toBe(200);}}
  await recovery.request.post("/api/v1/auth/logout",{headers});await admin.close();await user.close();await recovery.close();
 }
});
