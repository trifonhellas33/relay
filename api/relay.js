export const config = { runtime: "edge" };

// Επιτρεπτά hosts (όπως στο Deno). Αν χρειαστείς κι άλλο domain, πρόσθεσέ το εδώ.
const ALLOW = /(^|\.)(chaturbate\.[a-z.]+|mmcdn\.com|highwebmedia\.com)$/i;
// Προστασία από εσωτερικές διευθύνσεις (SSRF)
const BLOCK = /^(localhost|\[::1?\]|0\.0\.0\.0)$|\.(localhost|local|internal)$|^\[(fc|fd|fe[89ab])|^(127|10|0)\.|^169\.254\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./i;
// Endpoints λίστας που γίνονται cache για 45s
const LST = /\/(api\/ts\/roomlist\/room-list|directoryCams|models\/new)\/?$/i;

const UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Max-Age": "86400",
  "Access-Control-Expose-Headers": "content-type, content-length, content-range, accept-ranges",
};

const reply = (body, status = 200) =>
  new Response(body, { status, headers: { ...CORS, "Content-Type": "text/plain; charset=utf-8" } });

export default async function handler(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (!["GET", "HEAD", "POST"].includes(req.method)) return reply("method not allowed", 405);

  // Το key είναι υποχρεωτικό: χωρίς RELAY_KEY στο Vercel το relay μένει κλειστό
  const KEY = process.env.RELAY_KEY || "";
  const u = new URL(req.url);
  if (!KEY || u.searchParams.get("key") !== KEY) return reply("forbidden", 403);

  let target;
  try { target = new URL(u.searchParams.get("url") || ""); } catch (e) { return reply("invalid url", 400); }
  if (target.protocol !== "https:") return reply("https only", 400);
  if (BLOCK.test(target.hostname) || !ALLOW.test(target.hostname)) return reply("host not allowed", 403);

  const ref = u.searchParams.get("ref") || target.origin + "/";
  let origin = target.origin;
  try { origin = new URL(ref).origin; } catch (e) { /* ignore */ }

  const post = req.method === "POST";
  const h = new Headers({
    "User-Agent": UA,
    "Accept": req.headers.get("accept") || "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": ref,
    "Origin": origin,
    "sec-ch-ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Cookie": "agreeterms=1",
  });
  const xr = req.headers.get("x-requested-with"); if (xr) h.set("X-Requested-With", xr);
  const rg = req.headers.get("range"); if (rg) h.set("Range", rg);

  let body;
  if (post) {
    body = await req.text();
    h.set("Content-Type", req.headers.get("content-type") || "application/x-www-form-urlencoded");
    const t = crypto.randomUUID().replace(/-/g, "").toUpperCase();
    h.set("X-CSRFToken", t);
    h.set("Cookie", "agreeterms=1; csrftoken=" + t);
  }

  const ttl = req.method === "GET" && !rg && LST.test(target.pathname) ? 45 : 0;

  try {
    const up = await fetch(target, { method: req.method, headers: h, body, redirect: "follow" });

    // Περνάνε μόνο τα απαραίτητα headers (άρα δεν φεύγουν set-cookie, CSP, x-frame-options)
    const rh = new Headers(CORS);
    for (const k of ["content-type", "content-length", "content-range", "accept-ranges"]) {
      const v = up.headers.get(k); if (v) rh.set(k, v);
    }
    const ct = up.headers.get("content-type") || "";
    rh.set(
      "Cache-Control",
      up.status === 200 && ttl
        ? "public, s-maxage=" + ttl + ", stale-while-revalidate=30"
        : up.status === 200 && /^image\//i.test(ct)
          ? "public, max-age=300, s-maxage=300"
          : "no-store"
    );
    return new Response(req.method === "HEAD" ? null : up.body, { status: up.status, headers: rh });
  } catch (e) {
    return reply("upstream error: " + String(e), 502);
  }
      }
