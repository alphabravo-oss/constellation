import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { LIVE_EMAIL, LIVE_PASSWORD } from "./env";
import { totp } from "./totp";

const userEmail=`local-proof-${Date.now()}@example.test`;
const userPassword="local-browser-unique-Password-819!";

test("bootstrap administrator creates an analyst who signs in, is restricted, and is disabled",async({page,browser,baseURL})=>{
 test.setTimeout(120_000);
 await page.goto("/settings/users");
 await expect(page.getByRole("heading",{name:"Users",exact:true})).toBeVisible();
 await page.getByLabel("Email",{exact:true}).fill(userEmail);
 await page.getByLabel("Display name",{exact:true}).fill("Local proof analyst");
 await page.getByLabel("Password",{exact:true}).fill(userPassword);
 await page.getByRole("button",{name:"Create user",exact:true}).click();
 await expect(page.getByRole("heading",{name:"Account setup"})).toBeVisible();
 let seed=(await page.getByTestId("setup-totp").textContent())!;
 const row=page.getByRole("row").filter({has:page.getByText(userEmail,{exact:true})});await expect(row).toBeVisible();
 await row.getByRole("button",{name:"Reset TOTP",exact:true}).click();await expect(page.getByTestId("setup-totp")).not.toHaveText(seed);seed=(await page.getByTestId("setup-totp").textContent())!;
 await row.getByRole("button",{name:"Reset password",exact:true}).click();await page.getByLabel("New password",{exact:true}).fill(userPassword);
 await page.locator("form").filter({has:page.getByLabel("New password",{exact:true})}).getByRole("button",{name:"Reset password",exact:true}).click();
 await expect(page.getByTestId("setup-password")).toHaveText(userPassword);
 await row.getByRole("combobox").click();await page.getByRole("option",{name:"Auditor",exact:true}).click();await expect(row.getByRole("combobox")).toContainText("Auditor");
 await row.getByRole("combobox").click();await page.getByRole("option",{name:"Analyst",exact:true}).click();await expect(row.getByRole("combobox")).toContainText("Analyst");
 await page.screenshot({path:test.info().outputPath("users.png"),fullPage:true});
 // Secrets are visible only during setup and never in the list API.
 expect(JSON.stringify(await(await page.request.get("/api/v1/local-users")).json())).not.toContain(seed);
 const context=await browser.newContext({baseURL,storageState:{cookies:[],origins:[]}});
 try{
  const analyst=await context.newPage();await analyst.goto("/auth/login");
  await analyst.getByLabel("Email",{exact:true}).fill(userEmail);await analyst.getByLabel("Password",{exact:true}).fill(userPassword);await analyst.getByLabel("Authenticator code").fill(totp(seed));
  const axe=await new AxeBuilder({page:analyst}).withTags(["wcag2a","wcag2aa","wcag21aa"]).analyze();expect(axe.violations.filter(v=>v.impact==="serious"||v.impact==="critical")).toEqual([]);
  await analyst.getByRole("button",{name:"Sign in",exact:true}).click();await expect(analyst).toHaveURL(/\/clusters(?:[/?#]|$)/);
  expect((await(await context.request.get("/api/v1/auth/me")).json()).roles).toEqual(["Analyst"]);
  await expect(analyst.getByRole("link",{name:"Settings",exact:true})).toHaveCount(0);
  expect((await context.request.get("/api/v1/findings?limit=1")).status()).toBe(200);
  for(const path of ["/api/v1/local-users","/api/v1/settings/identity"])expect((await context.request.get(path)).status()).toBe(403);
  await analyst.screenshot({path:test.info().outputPath("analyst.png"),fullPage:true});
  await row.getByRole("button",{name:"Disable",exact:true}).click();await expect(row.getByRole("cell",{name:"disabled",exact:true})).toBeVisible();
  await expect.poll(async()=> (await context.request.get("/api/v1/auth/me")).status()).toBe(401);
  const refused=await context.request.post("/api/v1/auth/local",{headers:{Origin:baseURL!,"X-Constellation-Client":"browser"},data:{email:userEmail,password:userPassword,totp:totp(seed,1)}});expect(refused.status()).toBe(401);
 }finally{await context.close();}
});

test("local off refuses normal login; recovery works without SSO and the critical alert fires",async({browser,page,baseURL,request})=>{
 test.skip(!process.env.BREAK_GLASS_PASSWORD || !process.env.LIVE_TOTP_SECRET,"requires recovery and local setup material");test.setTimeout(150_000);
 const original=await(await page.request.get("/api/v1/settings/identity")).json();
 const recovery=await browser.newContext({baseURL,storageState:{cookies:[],origins:[]}});
 const headers={Origin:baseURL!,"X-Constellation-Client":"browser"};
 try{
  await page.goto("/settings/identity");
  await page.getByLabel("Local sign-in",{exact:true}).click();await page.getByRole("option",{name:"Disabled",exact:true}).click();
  const saved=page.waitForResponse(r=>r.url().endsWith("/api/v1/settings/identity")&&r.request().method()==="PUT");
  await page.getByRole("button",{name:"Save sign-in methods"}).click();expect((await saved).status()).toBe(200);
  const denied=await recovery.request.post("/api/v1/auth/local",{headers,data:{email:LIVE_EMAIL,password:LIVE_PASSWORD,totp:totp(process.env.LIVE_TOTP_SECRET!)}});expect(denied.status()).toBe(401);
  const rp=await recovery.newPage();await rp.goto("/auth/login");await expect(rp.getByLabel("Email",{exact:true})).toHaveCount(0);await expect(rp.getByRole("button",{name:"Continue with SSO"})).toHaveCount(0);
  await rp.getByRole("button",{name:"Emergency access",exact:true}).click();await rp.getByLabel("Password",{exact:true}).fill(process.env.BREAK_GLASS_PASSWORD!);await rp.getByLabel("Authenticator code").fill(totp(process.env.BREAK_GLASS_TOTP_SECRET!));
  await rp.getByRole("button",{name:"Sign in",exact:true}).click();await expect(rp).toHaveURL(/\/clusters(?:[/?#]|$)/);
  expect((await(await recovery.request.get("/api/v1/auth/me")).json()).email).toBe("break-glass@constellation.local");
  await rp.screenshot({path:test.info().outputPath("recovery-local-disabled.png"),fullPage:true});
  const prometheus=process.env.IDENTITY_PROOF_PROMETHEUS;
  if(prometheus)await expect.poll(async()=>{
   const r=await request.get(`${prometheus}/api/v1/query`,{params:{query:'ALERTS{alertname="ConstellationBreakGlassUsed",alertstate="firing"}'}});return(await r.json()).data.result.length;
  },{timeout:90_000,intervals:[1000,2000,5000]}).toBeGreaterThan(0);
 }finally{
  const current=await recovery.request.get("/api/v1/settings/identity");
  if(current.ok()){
   const v=await current.json();const restored=await recovery.request.put("/api/v1/settings/identity",{headers,data:{local:original.local,oidc:original.oidc,revision:v.revision}});expect(restored.status()).toBe(200);
  }
  await recovery.close();
 }
});

test("offline breached passwords, exponential account backoff and shared IP limit are enforced",async({browser,baseURL})=>{
 test.skip(!process.env.BREAK_GLASS_PASSWORD,"requires recovery setup material");test.setTimeout(150_000);
 // Previous proof consumed this recovery step. Wait for the next authenticator.
 await new Promise(resolve=>setTimeout(resolve,30_100-Date.now()%30_000));
 const context=await browser.newContext({baseURL,storageState:{cookies:[],origins:[]}});const headers={Origin:baseURL!,"X-Constellation-Client":"browser"};
 try{
  const login=await context.request.post("/api/v1/auth/break-glass",{headers,data:{password:process.env.BREAK_GLASS_PASSWORD!,totp:totp(process.env.BREAK_GLASS_TOTP_SECRET!)}});expect(login.status()).toBe(200);
  const breached=await context.request.post("/api/v1/local-users",{headers,data:{email:`breached-${Date.now()}@example.test`,display_name:"Breached proof",role:"Analyst",password:"password"}});expect(breached.status()).toBe(400);expect(await breached.text()).toContain("offline breached-password list");
  const email=`backoff-${Date.now()}@example.test`;
  const created=await context.request.post("/api/v1/local-users",{headers,data:{email,display_name:"Backoff proof",role:"Analyst",password:"unique-backoff-password-994!"}});expect(created.status()).toBe(200);
  for(let i=0;i<5;i++){const r=await context.request.post("/api/v1/auth/local",{headers,data:{email,password:"wrong",totp:"000000"}});expect(r.status()).toBe(401);}
  const backoff=await context.request.post("/api/v1/auth/local",{headers,data:{email,password:"wrong",totp:"000000"}});expect(backoff.status()).toBe(429);expect(backoff.headers()["retry-after"]).toBe("1");
  await new Promise(resolve=>setTimeout(resolve,1100));
  expect((await context.request.post("/api/v1/auth/local",{headers,data:{email,password:"wrong",totp:"000000"}})).status()).toBe(401);
  const longer=await context.request.post("/api/v1/auth/local",{headers,data:{email,password:"wrong",totp:"000000"}});expect(longer.status()).toBe(429);expect(longer.headers()["retry-after"]).toBe("2");
  let ipLimited=false;
  for(let i=0;i<25;i++){
   const r=await context.request.post("/api/v1/auth/local",{headers,data:{email:`missing-${i}@example.test`,password:"wrong",totp:"000000"}});
   if(r.status()===429 && r.headers()["retry-after"]==="60"){ipLimited=true;break;}
   expect(r.status()).toBe(401);
  }
  expect(ipLimited).toBeTruthy();
 }finally{await context.close();}
});
