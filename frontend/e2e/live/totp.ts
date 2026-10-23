import { createHmac } from "node:crypto";
export function totp(secret: string, offset=0): string {
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let bits="";
 for(const c of secret.replace(/=/g,"").toUpperCase())bits+=alphabet.indexOf(c).toString(2).padStart(5,"0");
 const bytes=Buffer.from(bits.match(/.{8}/g)!.map(b=>parseInt(b,2)));
 const step=Buffer.alloc(8);step.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)+offset));
 const h=createHmac("sha1",bytes).update(step).digest();const n=h[h.length-1]&15;
 return String((h.readUInt32BE(n)&0x7fffffff)%1000000).padStart(6,"0");
}
