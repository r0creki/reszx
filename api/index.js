import { supabase } from "../lib/supabase.js";
import { verifyUser, signUser } from "../lib/auth.js";
import jwt from "jsonwebtoken";
import axios from "axios";
import qs from "querystring";
import crypto from "crypto";

function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const part = () => Array.from({ length: 5 }, () =>
    chars[Math.floor(Math.random() * chars.length)]
  ).join("");
  return `PEVO-${part()}-${part()}-${part()}`;
}

function hashIp(ip) {
  return crypto.createHash('sha256').update(ip).digest('hex');
}

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

export default async function handler(req, res) {
  const { action } = req.query;

  try {
    // Login
    if (action === "login") {
      const state = generateCsrfToken();
      const params = new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        redirect_uri: process.env.REDIRECT_URI,
        response_type: "code",
        scope: "identify",
        state: state
      });
      
      await supabase.from("csrf_tokens").insert({
        token: state,
        created_at: Date.now(),
        used: false
      });
      
      return res.redirect(`https://discord.com/oauth2/authorize?${params}`);
    }

    // Callback
    if (action === "callback") {
      const { code, state } = req.query;
      
      const { data: csrf } = await supabase
        .from("csrf_tokens")
        .select("*")
        .eq("token", state)
        .maybeSingle();
        
      if (!csrf) return res.redirect("/?error=invalid_state");
      
      await supabase.from("csrf_tokens").delete().eq("token", state);

      try {
        const tokenResponse = await axios.post(
          "https://discord.com/api/oauth2/token",
          qs.stringify({
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            grant_type: "authorization_code",
            code,
            redirect_uri: process.env.REDIRECT_URI
          }),
          { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const userResponse = await axios.get(
          "https://discord.com/api/users/@me",
          { headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` } }
        );

        const jwtToken = signUser(userResponse.data);
        res.setHeader("Set-Cookie", `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`);
        return res.redirect("/");
      } catch (error) {
        return res.redirect("/");
      }
    }

    // Me
    if (action === "me") {
      const token = req.cookies.token;
      if (!token) return res.json({ authenticated: false });

      const user = verifyUser(token);
      if (!user) return res.json({ authenticated: false });

      const { data: userData } = await supabase
        .from("users")
        .select("*")
        .eq("discord_id", user.id)
        .maybeSingle();

      const { data: activeKey } = await supabase
        .from("keys")
        .select("label, expires_at")
        .eq("discord_id", user.id)
        .gt("expires_at", Date.now())
        .eq("banned", false)
        .maybeSingle();

      let status = "Free";
      if (activeKey) {
        if (activeKey.label === "Premium") status = "Premium";
        else if (activeKey.label === "Exclusive") status = "Exclusive";
        else status = activeKey.label;
      }

      return res.json({
        authenticated: true,
        user: {
          id: user.id,
          username: user.username,
          avatar: user.avatar,
          is_admin: userData?.is_admin || false,
          is_banned: userData?.is_banned || false,
          status: status,
          total_keys: userData?.total_keys || 0,
          created_at: userData?.created_at || null
        }
      });
    }

    // Workink - Generate Session dengan Signature
    if (action === "workink") {
      const token = req.cookies.token;
      if (!token) return res.status(401).json({ error: "Unauthorized" });

      const user = verifyUser(token);
      if (!user) return res.status(401).json({ error: "Invalid token" });

      // Cek apakah user sudah punya session aktif
      const { data: existingSession } = await supabase
        .from("workink_sessions")
        .select("*")
        .eq("discord_id", user.id)
        .eq("used", false)
        .gt("created_at", Date.now() - 300000)
        .maybeSingle();

      if (existingSession) {
        return res.status(429).json({ error: "Please wait before generating another link" });
      }

      const sessionId = crypto.randomBytes(32).toString('hex');
      const signature = crypto.createHmac('sha256', process.env.SECRET_SIGNATURE).update(sessionId).digest('hex');
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
      const userAgent = req.headers['user-agent'] || 'Unknown';
      const fingerprint = hashIp(ip + userAgent);

      await supabase.from("workink_sessions").insert({
        session_id: sessionId,
        signature: signature,
        discord_id: user.id,
        ip_address: ip,
        user_agent: userAgent,
        fingerprint: fingerprint,
        created_at: Date.now(),
        used: false
      });

      const encryptedSession = Buffer.from(JSON.stringify({
        id: sessionId,
        sig: signature.substring(0, 16),
        exp: Date.now() + 300000
      })).toString('base64');

      res.setHeader("Set-Cookie", [
        `workink_session=${encryptedSession}; HttpOnly; Path=/; Max-Age=300; SameSite=Lax; Secure`,
        `workink_fp=${fingerprint}; HttpOnly; Path=/; Max-Age=300; SameSite=Lax; Secure`
      ]);

      return res.json({
        success: true,
        workink_url: `https://work.ink/2jhr/pevolution-key`
      });
    }

    // Free-key - Validation Endpoint dengan Verifikasi Ganda
    if (action === "free-key") {
      const { token } = req.query;
      if (!token) return res.status(400).json({ valid: false });

      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
      const userAgent = req.headers['user-agent'] || 'Unknown';
      
      // Validasi format token Work.ink (UUID)
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(token)) {
        return res.status(400).json({ valid: false });
      }

      // Cek apakah token sudah pernah dipakai
      const { data: existingToken } = await supabase
        .from("pending_tokens")
        .select("*")
        .eq("token", token)
        .maybeSingle();

      if (existingToken) {
        return res.status(400).json({ valid: false });
      }

      // Simpan token dengan fingerprint
      const fingerprint = hashIp(ip + userAgent);
      await supabase.from("pending_tokens").insert({
        token: token,
        workink_ip: ip,
        user_agent: userAgent,
        fingerprint: fingerprint,
        created_at: Date.now(),
        used: false,
        expires_at: Date.now() + 300000
      });

      return res.json({ valid: true });
    }

    // Workink Callback - Destination URL dengan 5 Layer Security
    if (action === "workink-callback") {
      const encryptedSession = req.cookies.workink_session;
      const fingerprint = req.cookies.workink_fp;
      const userToken = req.cookies.token;
      const userIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
      const userAgent = req.headers['user-agent'] || 'Unknown';
      const referer = req.headers.referer || '';

      // LAYER 1: Validasi referer
      if (!referer.includes('work.ink')) {
        return res.redirect("/?error=invalid_source");
      }

      // LAYER 2: Validasi session cookie
      if (!encryptedSession || !fingerprint) {
        return res.redirect("/?error=invalid_session");
      }

      // LAYER 3: Decrypt dan validasi session
      let sessionData;
      try {
        sessionData = JSON.parse(Buffer.from(encryptedSession, 'base64').toString());
      } catch {
        return res.redirect("/?error=invalid_session");
      }

      const { data: session, error: sessionError } = await supabase
        .from("workink_sessions")
        .select("*")
        .eq("session_id", sessionData.id)
        .maybeSingle();

      if (sessionError || !session) return res.redirect("/?error=invalid_session");
      
      // LAYER 4: Validasi signature
      const expectedSignature = crypto.createHmac('sha256', process.env.SECRET_SIGNATURE).update(sessionData.id).digest('hex');
      if (session.signature !== expectedSignature) {
        return res.redirect("/?error=invalid_signature");
      }

      // LAYER 5: Validasi fingerprint
      const currentFingerprint = hashIp(userIp + userAgent);
      if (session.fingerprint !== currentFingerprint || fingerprint !== currentFingerprint) {
        return res.redirect("/?error=fingerprint_mismatch");
      }

      if (session.used) return res.redirect("/?error=already_used");
      if (Date.now() - session.created_at > 300000) return res.redirect("/?error=session_expired");

      // Cari token pending yang valid
      const { data: pendingToken, error: tokenError } = await supabase
        .from("pending_tokens")
        .select("*")
        .eq("used", false)
        .gt("expires_at", Date.now())
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (tokenError || !pendingToken) return res.redirect("/?error=no_token");

      // Verifikasi fingerprint token
      if (pendingToken.fingerprint !== currentFingerprint) {
        return res.redirect("/?error=token_fingerprint_mismatch");
      }

      // Mark semua sebagai used
      await supabase
        .from("pending_tokens")
        .update({ used: true, used_at: Date.now(), used_by_ip: userIp })
        .eq("token", pendingToken.token);

      await supabase
        .from("workink_sessions")
        .update({ used: true, used_at: Date.now(), workink_token: pendingToken.token })
        .eq("session_id", sessionData.id);

      // Bersihkan cookie
      res.setHeader("Set-Cookie", [
        `workink_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`,
        `workink_fp=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`
      ]);

      if (!userToken) return res.redirect("/?error=login_required");

      const user = verifyUser(userToken);
      if (!user) return res.redirect("/?error=invalid_session");
      if (session.discord_id !== user.id) return res.redirect("/?error=user_mismatch");

      const { data: existingKey } = await supabase
        .from("keys")
        .select("*")
        .eq("discord_id", user.id)
        .gt("expires_at", Date.now())
        .eq("banned", false)
        .maybeSingle();

      if (existingKey) {
        return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
      }

      const key = generateKey();
      const expiresAt = Date.now() + 7200000;
      const ipHash = hashIp(userIp);

      const { error: insertKeyError } = await supabase.from("keys").insert({
        key,
        discord_id: user.id,
        expires_at: expiresAt,
        created_at: Date.now(),
        label: "Free",
        used: true,
        ip_address: userIp,
        ip_hash: ipHash,
        last_used_at: Date.now(),
        user_agent: userAgent,
        workink_token: pendingToken.token,
        fingerprint: currentFingerprint
      });

      if (insertKeyError) {
        return res.redirect("/?error=key_generation_failed");
      }

      await supabase
        .from("users")
        .update({ total_keys: supabase.raw('COALESCE(total_keys, 0) + 1') })
        .eq("discord_id", user.id);

      return res.redirect(`/?key=${key}&exp=${expiresAt}`);
    }

    // Verify
    if (action === "verify") {
      const { key, hwid } = req.query;
      if (!key || !hwid) return res.json({ valid: false });

      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
      const hashedHwid = crypto.createHash("sha256").update(hwid + (process.env.SECRET_SIGNATURE || "dev_secret")).digest("hex");

      const { data: row, error: fetchError } = await supabase
        .from("keys")
        .select("*")
        .eq("key", key)
        .maybeSingle();

      if (fetchError || !row) return res.json({ valid: false });
      if (row.banned) return res.json({ valid: false });
      if (Date.now() > row.expires_at) {
        await supabase.from("keys").delete().eq("key", key);
        return res.json({ valid: false });
      }

      if (!row.hwid) {
        await supabase
          .from("keys")
          .update({ hwid, hwid_hash: hashedHwid, used: true, last_used_at: Date.now(), ip_address: ip })
          .eq("key", key);

        const payload = "print('Key Verified Secure!')";
        const signature = crypto.createHmac("sha256", process.env.SECRET_SIGNATURE || "dev_secret").update(payload).digest("hex");

        return res.json({ valid: true, payload, signature, expiresAt: row.expires_at, label: row.label });
      }

      if (row.hwid_hash !== hashedHwid) {
        const newFails = (row.failed_attempts || 0) + 1;
        if (newFails >= 3) {
          await supabase.from("keys").delete().eq("key", key);
          return res.json({ valid: false });
        }
        await supabase.from("keys").update({ failed_attempts: newFails }).eq("key", key);
        return res.json({ valid: false });
      }

      await supabase.from("keys").update({ last_used_at: Date.now(), ip_address: ip, failed_attempts: 0 }).eq("key", key);

      const payload = "print('Key Verified Secure!')";
      const signature = crypto.createHmac("sha256", process.env.SECRET_SIGNATURE || "dev_secret").update(payload).digest("hex");

      return res.json({ valid: true, payload, signature, expiresAt: row.expires_at, label: row.label });
    }

    // Redeem
    if (action === "redeem") {
      if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });

      const token = req.cookies.token;
      if (!token) return res.status(401).json({ error: "Unauthorized" });

      const user = verifyUser(token);
      if (!user) return res.status(401).json({ error: "Invalid token" });

      const { key } = req.body;
      if (!key) return res.status(400).json({ error: "Key required" });

      const { data: keyData, error: fetchError } = await supabase
        .from("keys")
        .select("*")
        .eq("key", key)
        .maybeSingle();

      if (fetchError || !keyData) return res.status(404).json({ error: "Invalid key" });
      if (Date.now() > keyData.expires_at) {
        await supabase.from("keys").delete().eq("key", key);
        return res.status(400).json({ error: "Key expired" });
      }
      if (keyData.used) return res.status(400).json({ error: "Key already used" });
      if (keyData.discord_id) return res.status(400).json({ error: "Key already claimed" });

      const { error: updateError } = await supabase
        .from("keys")
        .update({ discord_id: user.id, used: true })
        .eq("key", key);

      if (updateError) return res.status(500).json({ error: "Database error" });

      return res.json({ success: true });
    }

    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
    return res.status(500).json({ error: "Internal server error" });
  }
}
