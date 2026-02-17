import { supabase } from "../lib/supabase.js";
import { verifyUser, signUser } from "../lib/auth.js";
import jwt from "jsonwebtoken";
import axios from "axios";
import qs from "querystring";
import crypto from "crypto";

// ==================== HELPER FUNCTIONS ====================
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

// ==================== MAIN HANDLER ====================
export default async function handler(req, res) {
  const { action } = req.query; // ?action=login, ?action=me, ?action=free-key, ?action=workink-callback, dll

  // ========== LOGIN (Discord OAuth) ==========
  if (action === "login") {
    const params = new URLSearchParams({
      client_id: process.env.CLIENT_ID,
      redirect_uri: process.env.REDIRECT_URI,
      response_type: "code",
      scope: "identify"
    });
    return res.redirect(`https://discord.com/oauth2/authorize?${params}`);
  }

  // ========== CALLBACK (Discord OAuth) ==========
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

      res.setHeader(
        "Set-Cookie",
        `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
      );

      return res.redirect("/");
    } catch (error) {
      console.error("OAuth error:", error);
      return res.redirect("/");
    }
  }

  // ========== ME (Check user) ==========
  if (action === "me") {
    const token = req.cookies.token;

    if (!token) {
      return res.json({ authenticated: false });
    }

    try {
      const user = verifyUser(token);
      if (!user) {
        return res.json({ authenticated: false });
      }

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

      // Tentukan status
      let status = "Free";
      if (activeKey) {
        if (activeKey.label === "Premium" || activeKey.label?.includes("Premium")) {
          status = "Premium";
        } else if (activeKey.label === "Exclusive") {
          status = "Exclusive";
        } else {
          status = activeKey.label || "Free";
        }
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
    } catch (error) {
      return res.json({ authenticated: false });
    }
  }

  // ========== WORKINK (Generate Workink URL) ==========
  if (action === "workink") {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    try {
      const user = verifyUser(token);
      if (!user) {
        return res.status(401).json({ error: "Invalid token" });
      }

      // URL Workink dengan format: https://work.ink/2jhr/pevolution-key
      // TANPA {TOKEN} - Workink akan generate token sendiri
      const workinkUrl = `https://work.ink/2jhr/pevolution-key`;

      res.json({
        success: true,
        workink_url: workinkUrl
      });

    } catch (err) {
      console.error("Workink error:", err);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }

  // ========== FREE-KEY (VALIDATION ENDPOINT) ==========
  // Endpoint ini dipanggil oleh Work.ink untuk VALIDASI token
  // URL: /api?action=free-key&token=ABC123 (token dari Work.ink)
 if (action === "free-key") {
  const { token } = req.query;

  console.log("========== WORKINK VALIDATION ENDPOINT ==========");
  console.log("1. Raw token from URL:", token);
  console.log("2. All query params:", req.query);
  console.log("3. Request headers:", {
    userAgent: req.headers['user-agent'],
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
  });
  console.log("================================================");

  if (!token) {
    console.log("4. ERROR: No token provided");
    return res.status(400).json({ valid: false, error: "Token required" });
  }

  try {
    console.log("4. Processing token:", token);
    
    // Catat token yang divalidasi
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
               req.socket.remoteAddress || 
               'Unknown';

    console.log("5. IP Address:", ip);

    // Simpan log validasi
    try {
      await supabase.from("verification_logs").insert({
        key_text: "WORKINK_VALIDATION",
        ip_address: ip,
        success: true,
        error_reason: `Token: ${token}`,
        timestamp: Date.now()
      });
      console.log("6. Log saved to database");
    } catch (dbError) {
      console.error("6. Database error:", dbError.message);
      // Tetap lanjutkan walau database error
    }

    // Return success ke Work.ink
    console.log("7. Returning success response");
    return res.status(200).json({ 
      valid: true,
      info: {
        token: token,
        validated_at: Date.now()
      }
    });

  } catch (error) {
    console.error("❌ CATCH ERROR:", error);
    console.error("Error message:", error.message);
    console.error("Error stack:", error.stack);
    
    return res.status(500).json({ 
      valid: false, 
      error: "Server error",
      details: error.message 
    });
  }
}

  // ========== WORKINK-CALLBACK (DESTINATION URL) ==========
  // Endpoint ini adalah DESTINATION URL setelah user selesai di Work.ink
  // URL: /api?action=workink-callback
  if (action === "workink-callback") {
    console.log("========== WORKINK CALLBACK ==========");
    console.log("User redirected from Work.ink");

    try {
      // ====================================================
      // 1. AMBIL USER DARI COOKIE
      // ====================================================
      const userToken = req.cookies.token;
      if (!userToken) {
        console.log("No user token found");
        return res.redirect("/?error=login_required");
      }

      const user = verifyUser(userToken);
      if (!user) {
        console.log("Invalid user token");
        return res.redirect("/?error=invalid_session");
      }

      console.log("User authenticated:", user.username);

      // ====================================================
      // 2. DAPATKAN IP USER
      // ====================================================
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
                 req.socket.remoteAddress || 
                 'Unknown';
      const ipHash = hashIp(ip);
      const userAgent = req.headers['user-agent'] || 'Unknown';

      // ====================================================
      // 3. CEK ATAU BUAT USER DI DATABASE
      // ====================================================
      const { data: existingUser } = await supabase
        .from("users")
        .select("*")
        .eq("discord_id", user.id)
        .maybeSingle();

      if (!existingUser) {
        await supabase.from("users").insert({
          discord_id: user.id,
          discord_username: user.username,
          discord_avatar: user.avatar,
          created_at: Date.now(),
          last_login_at: Date.now(),
          last_login_ip: ip,
          login_count: 1
        });
      } else {
        await supabase
          .from("users")
          .update({
            last_login_at: Date.now(),
            last_login_ip: ip,
            login_count: existingUser.login_count + 1
          })
          .eq("discord_id", user.id);
      }

      // ====================================================
      // 4. CEK APAKAH USER SUDAH PUNYA KEY AKTIF
      // ====================================================
      const { data: existingKey } = await supabase
        .from("keys")
        .select("*")
        .eq("discord_id", user.id)
        .gt("expires_at", Date.now())
        .eq("banned", false)
        .maybeSingle();

      if (existingKey) {
        console.log("User already has active key:", existingKey.key);
        return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
      }

      // ====================================================
      // 5. GENERATE KEY BARU (2 JAM)
      // ====================================================
      const key = generateKey();
      const expiresAt = Date.now() + 2 * 60 * 60 * 1000;

      console.log("Generating new key:", key);

      await supabase.from("keys").insert({
        key,
        discord_id: user.id,
        expires_at: expiresAt,
        created_at: Date.now(),
        label: "Free",
        used: true,
        ip_address: ip,
        ip_hash: ipHash,
        last_used_at: Date.now(),
        user_agent: userAgent
      });

      // ====================================================
      // 6. UPDATE TOTAL KEYS USER
      // ====================================================
      await supabase
        .from("users")
        .update({
          total_keys: (existingUser?.total_keys || 0) + 1
        })
        .eq("discord_id", user.id);

      // ====================================================
      // 7. LOG SUKSES
      // ====================================================
      await supabase.from("verification_logs").insert({
        key_text: key,
        discord_id: user.id,
        ip_address: ip,
        ip_hash: ipHash,
        success: true,
        user_agent: userAgent,
        timestamp: Date.now()
      });

      console.log("Key generated successfully, redirecting...");
      
      // ====================================================
      // 8. REDIRECT KE HALAMAN UTAMA DENGAN KEY
      // ====================================================
      return res.redirect(`/?key=${key}&exp=${expiresAt}`);

    } catch (error) {
      console.error("Workink callback error:", error);
      return res.redirect("/?error=server_error");
    }
  }

  // ========== VERIFY (Key verification) ==========
  if (action === "verify") {
    const { key, hwid } = req.query;

    if (!key || !hwid) {
      return res.json({ valid: false, error: "Missing parameters" });
    }

    try {
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
                 req.socket.remoteAddress || 
                 'Unknown';

      const hashedHwid = crypto
        .createHash("sha256")
        .update(hwid + (process.env.SECRET_SIGNATURE || "dev_secret"))
        .digest("hex");

      const { data: row } = await supabase
        .from("keys")
        .select("*")
        .eq("key", key)
        .maybeSingle();

      if (!row) {
        return res.json({ valid: false, error: "Key not found" });
      }

      if (row.banned) {
        return res.json({ valid: false, error: "Key is banned" });
      }

      if (Date.now() > row.expires_at) {
        await supabase.from("keys").delete().eq("key", key);
        return res.json({ valid: false, error: "Key expired" });
      }

      if (!row.hwid) {
        await supabase
          .from("keys")
          .update({
            hwid: hwid,
            hwid_hash: hashedHwid,
            used: true,
            last_used_at: Date.now(),
            ip_address: ip
          })
          .eq("key", key);

        const payload = "print('Key Verified Secure!')";
        const signature = crypto
          .createHmac("sha256", process.env.SECRET_SIGNATURE || "dev_secret")
          .update(payload)
          .digest("hex");

        return res.json({
          valid: true,
          payload,
          signature,
          expiresAt: row.expires_at,
          label: row.label
        });
      }

      if (row.hwid_hash !== hashedHwid) {
        const newFails = (row.failed_attempts || 0) + 1;

        if (newFails >= 3) {
          await supabase.from("keys").delete().eq("key", key);
          return res.json({ valid: false, error: "Key deleted - too many attempts" });
        }

        await supabase
          .from("keys")
          .update({ failed_attempts: newFails })
          .eq("key", key);

        return res.json({ valid: false, error: "HWID mismatch" });
      }

      await supabase
        .from("keys")
        .update({
          last_used_at: Date.now(),
          ip_address: ip,
          failed_attempts: 0
        })
        .eq("key", key);

      const payload = "print('Key Verified Secure!')";
      const signature = crypto
        .createHmac("sha256", process.env.SECRET_SIGNATURE || "dev_secret")
        .update(payload)
        .digest("hex");

      return res.json({
        valid: true,
        payload,
        signature,
        expiresAt: row.expires_at,
        label: row.label
      });

    } catch (error) {
      console.error("Verify error:", error);
      return res.json({ valid: false, error: "Server error" });
    }
  }

  // ========== REDEEM (Redeem key) ==========
  if (action === "redeem") {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method Not Allowed" });
    }

    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    try {
      const user = verifyUser(token);
      if (!user) {
        return res.status(401).json({ error: "Invalid token" });
      }

      const { key } = req.body;
      if (!key) {
        return res.status(400).json({ error: "Key required" });
      }

      const { data: keyData } = await supabase
        .from("keys")
        .select("*")
        .eq("key", key)
        .maybeSingle();

      if (!keyData) {
        return res.status(404).json({ error: "Invalid key" });
      }

      if (Date.now() > keyData.expires_at) {
        await supabase.from("keys").delete().eq("key", key);
        return res.status(400).json({ error: "Key expired" });
      }

      if (keyData.used) {
        return res.status(400).json({ error: "Key already used" });
      }

      if (keyData.discord_id) {
        return res.status(400).json({ error: "Key already claimed" });
      }

      await supabase
        .from("keys")
        .update({
          discord_id: user.id,
          used: true
        })
        .eq("key", key);

      return res.json({ success: true });

    } catch (error) {
      console.error("Redeem error:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }

  // Jika action tidak dikenal
  return res.status(400).json({ error: "Invalid action" });
}
