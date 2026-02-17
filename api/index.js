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

async function cleanupOldSessions() {
  const expiryTime = Date.now() - 900000; // 15 menit
  await supabase
    .from("workink_sessions")
    .delete()
    .lt("created_at", expiryTime)
    .eq("used", false);
  
  await supabase
    .from("pending_tokens")
    .delete()
    .lt("created_at", expiryTime)
    .eq("used", false);
}

export default async function handler(req, res) {
  const { action } = req.query;

  try {
    // Cleanup session lama (jalankan di background)
    cleanupOldSessions().catch(() => {});

    // Login
    if (action === "login") {
      const params = new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        redirect_uri: process.env.REDIRECT_URI,
        response_type: "code",
        scope: "identify"
      });
      return res.redirect(`https://discord.com/oauth2/authorize?${params}`);
    }

    // Callback
    if (action === "callback") {
      const { code } = req.query;
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

    // Workink - Generate Session (15 MENIT)
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
        .gt("created_at", Date.now() - 900000)
        .maybeSingle();

      if (existingSession) {
        // Gunakan session yang sudah ada
        res.setHeader("Set-Cookie", `workink_session=${existingSession.session_id}; HttpOnly; Path=/; Max-Age=900; SameSite=Lax; Secure`);
        return res.json({
          success: true,
          workink_url: `https://work.ink/2jhr/pevolution-key`
        });
      }

      const sessionId = crypto.randomBytes(16).toString('hex');
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';

      await supabase.from("workink_sessions").insert({
        session_id: sessionId,
        discord_id: user.id,
        ip_address: ip,
        created_at: Date.now(),
        used: false
      });

      // Cookie 15 MENIT (900 detik)
      res.setHeader("Set-Cookie", `workink_session=${sessionId}; HttpOnly; Path=/; Max-Age=900; SameSite=Lax; Secure`);

      return res.json({
        success: true,
        workink_url: `https://work.ink/2jhr/pevolution-key`
      });
    }

    // Free-key - Validation Endpoint
    if (action === "free-key") {
      const { token } = req.query;
      if (!token) return res.status(400).json({ valid: false });

      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';

      await supabase.from("pending_tokens").insert({
        token: token,
        workink_ip: ip,
        created_at: Date.now(),
        used: false
      });

      return res.json({ valid: true });
    }

    // Workink Callback - Destination URL (15 MENIT)
    if (action === "workink-callback") {
      console.log("=== WORKINK CALLBACK ===");
      
      let sessionId = req.cookies.workink_session;
      const userToken = req.cookies.token;
      const userIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';
      const userAgent = req.headers['user-agent'] || 'Unknown';

      console.log("Session ID from cookie:", sessionId);
      console.log("User IP:", userIp);
      console.log("Has userToken:", !!userToken);

      // Fallback 1: Cari session berdasarkan IP
      if (!sessionId) {
        console.log("No session cookie, trying to find by IP:", userIp);
        const { data: recentSession } = await supabase
          .from("workink_sessions")
          .select("*")
          .eq("ip_address", userIp)
          .eq("used", false)
          .order("created_at", { ascending: false })
          .limit(1)
          .maybeSingle();
          
        if (recentSession) {
          sessionId = recentSession.session_id;
          console.log("Found session by IP:", sessionId);
        }
      }

      // Fallback 2: Cari session berdasarkan user token
      if (!sessionId && userToken) {
        const user = verifyUser(userToken);
        if (user) {
          console.log("Trying to find session by Discord ID:", user.id);
          const { data: userSession } = await supabase
            .from("workink_sessions")
            .select("*")
            .eq("discord_id", user.id)
            .eq("used", false)
            .order("created_at", { ascending: false })
            .limit(1)
            .maybeSingle();
            
          if (userSession) {
            sessionId = userSession.session_id;
            console.log("Found session by Discord ID:", sessionId);
          }
        }
      }

      if (!sessionId) {
        console.log("ERROR: No session found anywhere");
        return res.redirect("/?error=invalid_session");
      }

      const { data: session, error: sessionError } = await supabase
        .from("workink_sessions")
        .select("*")
        .eq("session_id", sessionId)
        .maybeSingle();

      if (sessionError || !session) {
        console.log("Session not in database:", sessionId);
        return res.redirect("/?error=invalid_session");
      }
      
      if (session.used) {
        console.log("Session already used");
        return res.redirect("/?error=already_used");
      }
      
      // Validasi 15 MENIT (900000 ms)
      if (Date.now() - session.created_at > 900000) {
        console.log("Session expired");
        return res.redirect("/?error=session_expired");
      }

      // Cari token pending
      const { data: pendingToken, error: tokenError } = await supabase
        .from("pending_tokens")
        .select("*")
        .eq("used", false)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (tokenError || !pendingToken) {
        console.log("No pending token found");
        return res.redirect("/?error=no_token");
      }

      // Cek apakah token juga expired (15 menit)
      if (Date.now() - pendingToken.created_at > 900000) {
        console.log("Token expired");
        await supabase.from("pending_tokens").delete().eq("token", pendingToken.token);
        return res.redirect("/?error=token_expired");
      }

      // Mark semua sebagai used
      await supabase
        .from("pending_tokens")
        .update({ used: true, used_at: Date.now() })
        .eq("token", pendingToken.token);

      await supabase
        .from("workink_sessions")
        .update({ used: true, used_at: Date.now(), workink_token: pendingToken.token })
        .eq("session_id", sessionId);

      // Hapus cookie
      res.setHeader("Set-Cookie", `workink_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`);

      if (!userToken) {
        console.log("No user token");
        return res.redirect("/?error=login_required");
      }

      const user = verifyUser(userToken);
      if (!user) {
        console.log("Invalid user token");
        return res.redirect("/?error=invalid_session");
      }
      
      if (session.discord_id !== user.id) {
        console.log("User mismatch");
        return res.redirect("/?error=user_mismatch");
      }

      // Cek apakah user sudah punya key aktif
      const { data: existingKey } = await supabase
        .from("keys")
        .select("*")
        .eq("discord_id", user.id)
        .gt("expires_at", Date.now())
        .eq("banned", false)
        .maybeSingle();

      if (existingKey) {
        console.log("User already has key:", existingKey.key);
        return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
      }

      // Generate key baru
      const key = generateKey();
      const expiresAt = Date.now() + 7200000; // 2 jam
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
        workink_token: pendingToken.token
      });

      if (insertKeyError) {
        console.log("Key generation failed:", insertKeyError);
        return res.redirect("/?error=key_generation_failed");
      }

      // Update total keys user
      await supabase
        .from("users")
        .update({ total_keys: supabase.raw('COALESCE(total_keys, 0) + 1') })
        .eq("discord_id", user.id);

      console.log("Key generated successfully:", key);
      return res.redirect(`/?key=${key}&exp=${expiresAt}`);
    }

    // Debug - Lihat cookies
    if (action === "debug-cookies") {
      return res.json({
        cookies: req.cookies,
        headers: {
          'user-agent': req.headers['user-agent'],
          'x-forwarded-for': req.headers['x-forwarded-for']
        },
        ip: req.socket.remoteAddress
      });
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
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}
