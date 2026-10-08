// ============================================================================
// paylink-tg-bridge — a small Cloudflare Worker that sits between PayLink
// and one or more Telebot Creator (TPY) bots.
//
// WHY THIS EXISTS (read this before changing anything):
//   1. PayLink's successUrl/cancelUrl redirect the customer's *browser*
//      somewhere. A browser can't "return to a Telegram chat" on its own --
//      it needs a https://t.me/<bot>?start=... deep link. PayLink itself has
//      no concept of bots/chats, so something has to translate between the
//      two. That's this Worker's /success and /cancel pages.
//   2. PayLink signs its webhook (POST to callbackUrl) with the merchant's
//      own PayLink API key (see PayLink's src/webhooks.js). TPY has no
//      general-purpose HMAC primitive available to verify that signature
//      itself (see the TPY docs: hashlib/md5/base64/re are available, a
//      generic hmac module is not), so a TPY command that received the
//      webhook directly would have to trust the payload blindly. This
//      Worker verifies the signature with real Web Crypto, and only then
//      forwards the (now-trusted) event to the bot's own TPY webhook URL.
//
// MULTI-TENANT BY DESIGN: this Worker holds NO merchant's PayLink API key of
// its own, and is not tied to one PayLink account. Every bot brings its own
// (already has to know it anyway, since it's the credential that bot's
// owner already got from their own PayLink /keys.html page) in the request
// body of POST /api/pay. That is the ONE secret that still exists anywhere
// in this picture -- and it lives exactly where it always did: in that
// bot's own TBC command. Nothing new to generate, nothing bridge-specific
// to manage. This is what lets any number of unrelated bots, each paid into
// their own separate PayLink wallet, share one deployment of this bridge.
//
// The only thing this Worker verifies on its own is that the *caller* really
// controls the Telegram bot it claims to -- using that bot's `bot_token`
// (already a free, built-in TPY system variable, nothing to paste) checked
// against Telegram's own getMe endpoint. That's what makes it safe to accept
// calls from bots this deployment has never seen before.
//
// HONEST TRADE-OFF: because /hook (PayLink's webhook) needs the same PayLink
// API key again later to verify the signature, that key is held in KV for
// up to ~1 hour per invoice (just long enough to cover the pay window) --
// not forever, and never logged -- but whoever operates/can read this
// Worker's KV does transiently have access to it. Fine when you and the
// other bots you share this with trust the same deployment (e.g. your own
// bots, or friends you've handed the URL to); if you ever offer this to
// strangers who shouldn't need to trust you with their PayLink key, that's
// the thing to redesign first.
//
// ROUTES
//   POST /api/pay              create an invoice on the calling bot's behalf
//   POST /hook?rid=..          PayLink's callbackUrl target
//   GET  /success?rid=..       customer's browser lands here
//   GET  /cancel?rid=..        ...or here
//   GET  /                     health check
// ============================================================================

function json(data, status) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}
function html(body, status = 200) {
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=UTF-8" } });
}
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Confirms `token` is a real, currently-valid Telegram bot token by asking
// Telegram itself (nobody but the bot's real owner can produce a token that
// passes this), and returns that bot's username -- so the caller never has
// to tell us (or hardcode) its own username either. Cached in KV for an hour
// per token so a busy bot isn't hitting Telegram's API on every /pay call.
async function verifyBotToken(token, env) {
  if (!token || !/^\d+:[A-Za-z0-9_-]{30,50}$/.test(token)) return null;

  const cacheKey = `tgbot:${await sha256Hex(token)}`;
  const cached = await env.RID_MAP.get(cacheKey, "json");
  if (cached) return cached.username;

  let res;
  try {
    res = await fetch(`https://api.telegram.org/bot${token}/getMe`);
  } catch {
    return null;
  }
  if (!res.ok) return null;
  const data = await res.json().catch(() => null);
  if (!data || !data.ok || !data.result || !data.result.username) return null;

  await env.RID_MAP.put(cacheKey, JSON.stringify({ username: data.result.username }), { expirationTtl: 3600 });
  return data.result.username;
}

function genRid() {
  return [...crypto.getRandomValues(new Uint8Array(9))].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmacHex(payload, key) {
  const cryptoKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(payload));
  return bytesToHex(new Uint8Array(sig));
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// A Telegram /start deep-link payload may only contain [A-Za-z0-9_-], up to
// 64 chars. Our rid is already hex (safe); the prefix stays well under that.
function startParamFor(prefix, rid) {
  return `${prefix}_${rid}`.slice(0, 64);
}

const PAGE_CSS = `
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#F5F4FE;font-family:'Hind Siliguri',system-ui,sans-serif;padding:24px;}
  .card{max-width:380px;width:100%;background:#fff;border-radius:24px;padding:36px 26px;
    text-align:center;box-shadow:0 24px 50px -24px rgba(23,19,39,.3);}
  .icon{width:64px;height:64px;border-radius:50%;margin:0 auto 18px;display:flex;
    align-items:center;justify-content:center;font-size:30px;}
  .good{background:#E8F8EE;color:#1E9E5A;} .bad{background:#FDEBEC;color:#D8283D;}
  h1{font-size:19px;margin:0 0 8px;color:#171327;}
  p{font-size:13.5px;color:#78748F;line-height:1.7;margin:0 0 22px;}
  a.btn{display:inline-block;background:linear-gradient(135deg,#6C5CE7,#4B3AD1);color:#fff;
    text-decoration:none;font-weight:700;padding:14px 26px;border-radius:14px;font-size:14.5px;}
  .note{margin-top:14px;font-size:11.5px;color:#9F9BB8;}
`;

function redirectPage({ good, title, message, botUsername, startParam }) {
  const botLink = botUsername ? `https://t.me/${botUsername}?start=${startParam}` : null;
  const autoRedirect = botLink
    ? `<meta http-equiv="refresh" content="2;url=${botLink}"><script>setTimeout(function(){location.href=${JSON.stringify(botLink)};},1500);</script>`
    : "";
  return `<!doctype html><html lang="bn"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>${autoRedirect}<style>${PAGE_CSS}</style></head><body>
<div class="card">
  <div class="icon ${good ? "good" : "bad"}">${good ? "✅" : "⏰"}</div>
  <h1>${title}</h1>
  <p>${message}</p>
  ${botLink ? `<a class="btn" href="${botLink}">বটে ফিরে যান</a><div class="note">স্বয়ংক্রিয়ভাবে কয়েক সেকেন্ডে নিয়ে যাওয়া হচ্ছে…</div>` : ""}
</div></body></html>`;
}

async function handlePay(request, env) {
  let body;
  try { body = await request.json(); } catch { body = {}; }

  const amount = Number(body.amount);
  const botToken = String(body.botToken || "").trim();
  const webhookUrl = String(body.webhookUrl || "").trim();
  const paylinkApiKey = String(body.paylinkApiKey || "").trim();
  const paylinkBaseUrl = String(body.paylinkBaseUrl || env.PAYLINK_BASE_URL || "").trim().replace(/\/+$/, "");
  const reference = body.reference ? String(body.reference).slice(0, 128) : null;

  if (!amount || amount <= 0) return json({ error: "amount আবশ্যক এবং ধনাত্মক হতে হবে।" }, 400);
  if (!webhookUrl || !/^https?:\/\//i.test(webhookUrl)) return json({ error: "webhookUrl আবশ্যক এবং একটি বৈধ http(s) ঠিকানা হতে হবে।" }, 400);
  if (!paylinkApiKey) return json({ error: "paylinkApiKey আবশ্যক — আপনার নিজের PayLink /keys.html পেজ থেকে নিন।" }, 400);
  if (!paylinkBaseUrl) return json({ error: "paylinkBaseUrl আবশ্যক (অথবা এই Worker-এ PAYLINK_BASE_URL ডিফল্ট সেট করুন)।" }, 400);

  const botUsername = await verifyBotToken(botToken, env);
  if (!botUsername) return json({ error: "botToken যাচাই করা যায়নি — এটা কি সঠিক ও বৈধ Telegram bot token?" }, 401);

  const rid = genRid();
  const origin = new URL(request.url).origin;

  // Keep the rid -> {webhookUrl, botUsername, paylinkApiKey, paylinkBaseUrl}
  // mapping around for ~1 hour -- comfortably longer than PayLink's default
  // 15-minute invoice TTL. paylinkApiKey has to be here too: /hook needs the
  // SAME key back later to verify that invoice's webhook signature, since
  // each bot may be using an entirely different PayLink account.
  await env.RID_MAP.put(
    rid,
    JSON.stringify({ webhookUrl, botUsername, paylinkApiKey, paylinkBaseUrl, createdAt: Date.now() }),
    { expirationTtl: 3600 }
  );

  let res, raw;
  try {
    res = await fetch(`${paylinkBaseUrl}/api/invoices`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${paylinkApiKey}` },
      body: JSON.stringify({
        amount,
        reference: reference || rid,
        callbackUrl: `${origin}/hook?rid=${rid}`,
        successUrl: `${origin}/success?rid=${rid}`,
        cancelUrl: `${origin}/cancel?rid=${rid}`,
      }),
    });
    raw = await res.text();
  } catch (e) {
    return json({ error: `PayLink-এ পৌঁছানো যায়নি: ${e.message}` }, 502);
  }

  const data = (() => { try { return JSON.parse(raw); } catch { return null; } })();
  if (!res.ok || !data || !data.payUrl) {
    return json({ error: (data && data.error) || `PayLink error (HTTP ${res.status})` }, res.status || 502);
  }

  return json({ payUrl: data.payUrl, invoiceId: data.id, rid }, 201);
}

async function handleHook(request, env, ctx) {
  const rid = new URL(request.url).searchParams.get("rid");
  const raw = await request.text(); // must hash the EXACT raw body, before any parsing
  const signature = request.headers.get("X-Signature") || "";

  if (!rid) return json({ ok: true }, 200);
  const mapping = await env.RID_MAP.get(rid, "json");
  if (!mapping) return json({ ok: true, forwarded: false }, 200); // expired/unknown rid -- nothing we can verify against

  const expected = await hmacHex(raw, mapping.paylinkApiKey);
  if (!signature || !constantTimeEqual(signature, expected)) {
    return json({ error: "Invalid signature." }, 401);
  }

  const payload = (() => { try { return JSON.parse(raw); } catch { return null; } })();
  if (!payload || payload.event !== "invoice.verified") return json({ ok: true }, 200);
  if (!mapping.webhookUrl) return json({ ok: true, forwarded: false }, 200);

  const forward = fetch(mapping.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).catch(() => {});

  if (ctx && ctx.waitUntil) ctx.waitUntil(forward); else await forward;
  return json({ ok: true, forwarded: true }, 200);
}

async function handleRedirectPage(request, env, good) {
  const url = new URL(request.url);
  const rid = url.searchParams.get("rid");
  const status = url.searchParams.get("status") || (good ? "verified" : "cancelled");
  const mapping = rid ? await env.RID_MAP.get(rid, "json") : null;
  const botUsername = mapping ? mapping.botUsername : null;

  if (good) {
    return html(redirectPage({
      good: true,
      title: "পেমেন্ট সফল হয়েছে! ✅",
      message: "ধন্যবাদ! আপনার পেমেন্ট সফলভাবে সম্পন্ন হয়েছে।",
      botUsername,
      startParam: startParamFor("paid", rid || "0"),
    }));
  }

  const isExpired = status === "expired";
  return html(redirectPage({
    good: false,
    title: isExpired ? "মেয়াদ শেষ হয়ে গেছে" : "পেমেন্ট বাতিল হয়েছে",
    message: isExpired
      ? "এই পেমেন্ট লিংকটির মেয়াদ শেষ হয়ে গেছে। বটে গিয়ে আবার চেষ্টা করুন।"
      : "আপনি পেমেন্ট থেকে বের হয়ে এসেছেন।",
    botUsername,
    startParam: startParamFor(isExpired ? "expired" : "cancelled", rid || "0"),
  }));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/pay" && request.method === "POST") return await handlePay(request, env);
      if (url.pathname === "/hook" && request.method === "POST") return await handleHook(request, env, ctx);
      if (url.pathname === "/success" && request.method === "GET") return await handleRedirectPage(request, env, true);
      if (url.pathname === "/cancel" && request.method === "GET") return await handleRedirectPage(request, env, false);
      if (url.pathname === "/") return html("<p style='font-family:sans-serif'>PayLink Telegram Bridge চালু আছে।</p>");
      return json({ error: "Not found." }, 404);
    } catch (e) {
      return json({ error: "Internal error.", detail: String(e && e.message) }, 500);
    }
  },
};
