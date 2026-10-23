import { expect, test } from "@playwright/test";
import { authStatePath, storageStatePath, writeAuthState } from "./auth-state";
import { CREDS, oidcLogin } from "./utils";
const API=process.env.VITE_API_URL??"https://constellation.dev.alphabravo.io";
test("prepare browser and API authentication through OIDC",async({page})=>{
 await oidcLogin(page);const storage=await page.context().storageState({path:storageStatePath});
 const cookies=storage.cookies.filter(c=>c.name==="__Host-constellation-session");expect(cookies).toHaveLength(1);
 writeAuthState({api:API,email:CREDS.email,token:cookies[0].value,cookies});
 test.info().annotations.push({type:"auth-state",description:authStatePath});
});
