/**
 * Push-up Lock: subscription server
 *
 * Flow:
 *  1. App sends the user's Supabase JWT to POST /api/subscriptions/create
 *  2. Server creates a PayPal subscription (custom_id = user id) and returns an approval URL
 *  3. App opens the URL in a browser tab; the user approves on PayPal
 *  4. PayPal calls POST /api/paypal/webhook; the server verifies the signature,
 *     re-fetches the subscription from PayPal (source of truth) and saves it in Supabase
 *  5. App calls GET /api/subscriptions/status (or POST /api/subscriptions/sync
 *     right after returning from PayPal) and caches the result locally
 *
 * Needs Node 18+ (uses the built-in fetch).
 */

require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

// ---------- Config ----------
const {
  PORT = 3000,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  PAYPAL_ENV = "sandbox", // "sandbox" or "live"
  PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET,
  PAYPAL_PLAN_ID,
  PAYPAL_WEBHOOK_ID,
  RETURN_URL,
  CANCEL_URL,
  BRAND_NAME = "Push-up Lock",
} = process.env;

const required = {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  PAYPAL_CLIENT_ID,
  PAYPAL_CLIENT_SECRET,
  PAYPAL_PLAN_ID,
  PAYPAL_WEBHOOK_ID,
  RETURN_URL,
  CANCEL_URL,
};
const missing = Object.entries(required)
  .filter(([, v]) => !v)
  .map(([k]) => k);
if (missing.length) {
  console.error(`Missing environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

const PAYPAL_BASE =
  PAYPAL_ENV === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";

// The service-role key bypasses row-level security. Never ship it in the app.
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// ---------- PayPal helpers ----------
let tokenCache = { value: null, expiresAt: 0 };

async function getPayPalToken() {
  if (tokenCache.value && Date.now() < tokenCache.expiresAt - 60_000) {
    return tokenCache.value;
  }
  const basic = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`
  ).toString("base64");

  const res = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  if (!res.ok) throw new Error(`PayPal auth failed (${res.status})`);

  const data = await res.json();
  tokenCache = {
    value: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  };
  return tokenCache.value;
}

async function paypal(path, options = {}) {
  const token = await getPayPalToken();
  const res = await fetch(`${PAYPAL_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const err = new Error(`PayPal ${path} failed (${res.status})`);
    err.details = body;
    throw err;
  }
  return body;
}

async function verifyWebhookSignature(req) {
  const h = req.headers;
  const result = await paypal("/v1/notifications/verify-webhook-signature", {
    method: "POST",
    body: JSON.stringify({
      auth_algo: h["paypal-auth-algo"],
      cert_url: h["paypal-cert-url"],
      transmission_id: h["paypal-transmission-id"],
      transmission_sig: h["paypal-transmission-sig"],
      transmission_time: h["paypal-transmission-time"],
      webhook_id: PAYPAL_WEBHOOK_ID,
      webhook_event: req.body,
    }),
  });
  return result.verification_status === "SUCCESS";
}

// ---------- Subscription logic ----------

/**
 * Fetch a subscription from PayPal and save it in Supabase.
 * PayPal is the source of truth, so we never trust the webhook payload alone.
 */
async function syncSubscription(paypalSubscriptionId) {
  const sub = await paypal(
    `/v1/billing/subscriptions/${encodeURIComponent(paypalSubscriptionId)}`
  );

  if (sub.plan_id !== PAYPAL_PLAN_ID) {
    console.warn(`Ignoring subscription ${sub.id}: unexpected plan ${sub.plan_id}`);
    return null;
  }

  const userId = sub.custom_id;
  if (!userId) {
    console.warn(`Subscription ${sub.id} has no custom_id, cannot link to a user`);
    return null;
  }

  // Keep the old period end if PayPal no longer reports one (e.g. cancelled).
  const { data: existing } = await supabase
    .from("subscriptions")
    .select("current_period_end")
    .eq("user_id", userId)
    .maybeSingle();

  const nextBilling = sub.billing_info?.next_billing_time || null;
  const periodEnd = nextBilling || existing?.current_period_end || null;

  const row = {
    user_id: userId,
    paypal_subscription_id: sub.id,
    plan_id: sub.plan_id,
    status: sub.status, // APPROVAL_PENDING | APPROVED | ACTIVE | SUSPENDED | CANCELLED | EXPIRED
    current_period_end: periodEnd,
    updated_at: new Date().toISOString(),
  };

  const { error } = await supabase
    .from("subscriptions")
    .upsert(row, { onConflict: "user_id" });
  if (error) throw error;

  return row;
}

function hasAccess(row) {
  if (!row) return false;
  if (row.status === "ACTIVE") return true;
  // A cancelled subscription stays valid until the paid period ends.
  if (row.status === "CANCELLED" && row.current_period_end) {
    return new Date(row.current_period_end).getTime() > Date.now();
  }
  return false;
}

function publicStatus(row) {
  return {
    has_access: hasAccess(row),
    status: row?.status || "NONE",
    current_period_end: row?.current_period_end || null,
    checked_at: new Date().toISOString(),
  };
}

// ---------- App ----------
const app = express();
app.set("trust proxy", 1); // needed behind Render/Railway/Fly/nginx for correct IPs
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));

// Verifies the Supabase JWT sent by the app.
async function requireUser(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing bearer token" });

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return res.status(401).json({ error: "Invalid token" });

  req.user = data.user;
  next();
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// Start a subscription: returns a PayPal approval URL for the app to open.
app.post("/api/subscriptions/create", requireUser, async (req, res) => {
  try {
    const { data: existing } = await supabase
      .from("subscriptions")
      .select("*")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (hasAccess(existing)) {
      return res.status(409).json({ error: "Already subscribed", ...publicStatus(existing) });
    }

    const sub = await paypal("/v1/billing/subscriptions", {
      method: "POST",
      headers: { "PayPal-Request-Id": `${req.user.id}-${Date.now()}` },
      body: JSON.stringify({
        plan_id: PAYPAL_PLAN_ID,
        custom_id: req.user.id,
        subscriber: req.user.email ? { email_address: req.user.email } : undefined,
        application_context: {
          brand_name: BRAND_NAME,
          user_action: "SUBSCRIBE_NOW",
          shipping_preference: "NO_SHIPPING",
          return_url: RETURN_URL,
          cancel_url: CANCEL_URL,
        },
      }),
    });

    const approveUrl = sub.links?.find((l) => l.rel === "approve")?.href;
    if (!approveUrl) throw new Error("PayPal did not return an approval link");

    // Save as pending so we can sync it later even if the webhook is slow.
    const { error } = await supabase.from("subscriptions").upsert(
      {
        user_id: req.user.id,
        paypal_subscription_id: sub.id,
        plan_id: PAYPAL_PLAN_ID,
        status: sub.status || "APPROVAL_PENDING",
        updated_at: new Date().toISOString(),
      },
      { onConflict: "user_id" }
    );
    if (error) throw error;

    res.json({ approve_url: approveUrl, subscription_id: sub.id });
  } catch (err) {
    console.error("create:", err.message, err.details || "");
    res.status(500).json({ error: "Could not start subscription" });
  }
});

// Current status from our database (fast; the app caches this).
app.get("/api/subscriptions/status", requireUser, async (req, res) => {
  const { data, error } = await supabase
    .from("subscriptions")
    .select("*")
    .eq("user_id", req.user.id)
    .maybeSingle();

  if (error) {
    console.error("status:", error.message);
    return res.status(500).json({ error: "Could not load status" });
  }
  res.json(publicStatus(data));
});

// Re-check with PayPal. Call this right after the user returns from checkout.
app.post("/api/subscriptions/sync", requireUser, async (req, res) => {
  try {
    const { data: existing } = await supabase
      .from("subscriptions")
      .select("*")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (!existing?.paypal_subscription_id) return res.json(publicStatus(null));

    const row = await syncSubscription(existing.paypal_subscription_id);
    res.json(publicStatus(row || existing));
  } catch (err) {
    console.error("sync:", err.message, err.details || "");
    res.status(500).json({ error: "Could not sync subscription" });
  }
});

// Cancel at the user's request. Access continues until the paid period ends.
app.post("/api/subscriptions/cancel", requireUser, async (req, res) => {
  try {
    const { data: existing } = await supabase
      .from("subscriptions")
      .select("*")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (!existing?.paypal_subscription_id) {
      return res.status(404).json({ error: "No subscription found" });
    }

    await paypal(
      `/v1/billing/subscriptions/${encodeURIComponent(existing.paypal_subscription_id)}/cancel`,
      { method: "POST", body: JSON.stringify({ reason: "Cancelled by user" }) }
    );

    const row = await syncSubscription(existing.paypal_subscription_id);
    res.json(publicStatus(row || existing));
  } catch (err) {
    console.error("cancel:", err.message, err.details || "");
    res.status(500).json({ error: "Could not cancel subscription" });
  }
});

// PayPal webhook. Configure this URL in the PayPal developer dashboard.
app.post("/api/paypal/webhook", async (req, res) => {
  try {
    const valid = await verifyWebhookSignature(req);
    if (!valid) {
      console.warn("Rejected webhook with invalid signature");
      return res.sendStatus(400);
    }

    const event = req.body;
    const type = event.event_type || "";
    const resource = event.resource || {};

    // Subscription events carry the subscription id in resource.id.
    // Payment events (PAYMENT.SALE.*) reference it as billing_agreement_id.
    const subscriptionId = type.startsWith("BILLING.SUBSCRIPTION.")
      ? resource.id
      : resource.billing_agreement_id;

    const handled = [
      "BILLING.SUBSCRIPTION.ACTIVATED",
      "BILLING.SUBSCRIPTION.UPDATED",
      "BILLING.SUBSCRIPTION.RE-ACTIVATED",
      "BILLING.SUBSCRIPTION.CANCELLED",
      "BILLING.SUBSCRIPTION.SUSPENDED",
      "BILLING.SUBSCRIPTION.EXPIRED",
      "BILLING.SUBSCRIPTION.PAYMENT.FAILED",
      "PAYMENT.SALE.COMPLETED",
    ];

    if (handled.includes(type) && subscriptionId) {
      await syncSubscription(subscriptionId);
    }

    res.sendStatus(200);
  } catch (err) {
    console.error("webhook:", err.message, err.details || "");
    res.sendStatus(500); // PayPal will retry
  }
});

// Pages PayPal sends the user to after checkout. They hand the user back to the app
// through the pushlock:// deep link. Set RETURN_URL and CANCEL_URL to these two pages.
function returnPage(title, text, deepLink) {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="1;url=${deepLink}">
<title>${title}</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0c0f;color:#f4f6f8;font-family:system-ui,sans-serif;text-align:center}
main{padding:32px;max-width:360px}h1{font-size:26px;margin:0 0 8px}p{color:#8a93a3;line-height:1.5}
a{display:inline-block;margin-top:24px;padding:16px 28px;border-radius:16px;background:#c6ff3d;color:#0a0c0f;font-weight:700;text-decoration:none}
</style></head><body><main><h1>${title}</h1><p>${text}</p>
<a href="${deepLink}">Open Push-up Lock</a></main></body></html>`;
}

app.get("/subscribed", (_req, res) =>
  res.type("html").send(returnPage("You're subscribed", "Thanks! Head back to the app to finish setting up.", "pushlock://subscribed"))
);
app.get("/cancelled", (_req, res) =>
  res.type("html").send(returnPage("Checkout cancelled", "No charge was made. You can subscribe any time from the app.", "pushlock://cancelled"))
);

app.use((_req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} (PayPal ${PAYPAL_ENV})`);
});
