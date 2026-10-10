export const config = { runtime: "edge" };

const ALLOW = /(^|\.)(chaturbate\.[a-z.]+|mmcdn\.com|highwebmedia\.com)$/i;
const UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "x-requested-with, content-type, range, accept",
  "Access-Control-Expose-Headers": "content-length, content-range, accept-ranges",
};
const reply = (body, status) => new Response(body, { status, headers: CORS });

export default async function handler(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const KEY = process.env.RELAY_KEY || "";
  const u = new URL(req.url);
  if (!KEY || u.searchParams.get("key") !== KEY) return reply("forbidden", 403);
  let target;
  try { target = new URL(u.searchParams.get("url") || ""); } catch (e) { return reply("bad url", 400); }
  if (target.protocol !== "https:" || !ALLOW.test(target.hostname)) return reply("host not allowed", 400);
  const ref = u.searchParams.get("ref") || target.origin + "/";
  let origin = target.origin;
  try { origin = new URL(ref).origin; } catch (e) {}
  const h = new Headers();
  h.set("User-Agent", UA);
  h.set("Referer", ref);
  h.set("Origin", origin);
  h.set("Accept", req.headers.get("accept") || "*/*");
  h.set("Accept-Language", "en-US,en;q=0.9");
  const xr = req.headers.get("x-requested-with"); if (xr) h.set("X-Requested-With", xr);
  const rg = req.headers.get("range"); if (rg) h.set("Range", rg);
  const post = req.method === "POST";
  let body;
  if (post) {
    body = await req.text();
    h.set("Content-Type", req.headers.get("content-type") || "application/x-www-form-urlencoded");
    const t = crypto.randomUUID().replace(/-/g, "").toUpperCase();
    h.set("X-CSRFToken", t);
    h.set("Cookie", "csrftoken=" + t);
  }
  try {
    const up = await fetch(target, { method: req.method === "HEAD" ? "HEAD" : post ? "POST" : "GET", headers: h, body, redirect: "follow" });
    const rh = new Headers(CORS);
    for (const k of ["content-type", "content-length", "content-range", "accept-ranges", "cache-control"]) {
      const v = up.headers.get(k); if (v) rh.set(k, v);
    }
    return new Response(up.body, { status: up.status, headers: rh });
  } catch (e) {
    return reply("upstream error: " + String(e), 502);
  }
}
