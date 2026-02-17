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
  const { action } = req.query;

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

  // ========== WORKINK (Generate Workink URL & Session) ==========
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

      // Generate unique session ID
      const sessionId = crypto.randomBytes(16).toString('hex');
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
                 req.socket.remoteAddress || 
                 'Unknown';

      // Simpan session ke database
      await supabase.from("workink_sessions").insert({
        session_id: sessionId,
        discord_id: user.id,
        ip_address: ip,
        created_at: Date.now(),
        validated: false,
        used: false
      });

      // Set cookie session (5 menit)
      res.setHeader(
        "Set-Cookie",
        `workink_session=${sessionId}; HttpOnly; Path=/; Max-Age=300; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
      );

      // URL Workink
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
  if (action === "free-key") {
    const { token } = req.query;

    console.log("========== WORKINK VALIDATION ==========");
    console.log("Token received:", token);

    if (!token) {
      return res.status(400).json({ valid: false });
    }

    try {
      // Ambil session dari cookie
      const sessionId = req.cookies.workink_session;
      
      if (!sessionId) {
        console.log("No session cookie found");
        return res.status(400).json({ valid: false });
      }

      // Update session bahwa token sudah divalidasi
      const { error } = await supabase
        .from("workink_sessions")
        .update({ 
          workink_token: token,
          validated: true,
          validated_at: Date.now() 
        })
        .eq("session_id", sessionId);

      if (error) {
        console.error("Database error:", error);
        return res.status(500).json({ valid: false });
      }

      console.log("Session updated, token valid");
      
      // Return success ke Work.ink
      return res.json({ 
        valid: true,
        info: {
          token: token,
          validated_at: Date.now()
        }
      });

    } catch (error) {
      console.error("Validation error:", error);
      return res.status(500).json({ valid: false });
    }
  }

  // ========== WORKINK-CALLBACK (DESTINATION URL) ==========
  if (action === "workink-callback") {
    console.log("========== WORKINK CALLBACK ==========");

    try {
      // ====================================================
      // 1. CEK SESSION COOKIE
      // ====================================================
      const sessionId = req.cookies.workink_session;
      const userToken = req.cookies.token;
      const referer = req.headers.referer || '';
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
                 req.socket.remoteAddress || 
                 'Unknown';

      console.log("Session ID:", sessionId);
      console.log("Referer:", referer);
      console.log("IP:", ip);

      // Validasi 1: Harus ada session
      if (!sessionId) {
        console.log("BYPASS ATTEMPT: No session cookie");
        return res.redirect("/?error=invalid_session");
      }

      // Validasi 2: Harus dari Work.ink (minimal pencegahan dasar)
      if (!referer.includes('work.ink')) {
        console.log("BYPASS ATTEMPT: Invalid referer", referer);
        return res.redirect("/?error=invalid_source");
      }

      // ====================================================
      // 2. CEK SESSION DI DATABASE
      // ====================================================
      const { data: session, error } = await supabase
        .from("workink_sessions")
        .select("*")
        .eq("session_id", sessionId)
        .single();

      if (error || !session) {
        console.log("BYPASS ATTEMPT: Session not found in database");
        return res.redirect("/?error=invalid_session");
      }

      console.log("Session found:", {
        discord_id: session.discord_id,
        validated: session.validated,
        used: session.used,
        created_at: new Date(session.created_at).toISOString()
      });

      // Validasi 3: Token harus sudah divalidasi
      if (!session.validated) {
        console.log("BYPASS ATTEMPT: Token not validated");
        return res.redirect("/?error=not_validated");
      }

      // Validasi 4: Session belum pernah dipakai
      if (session.used) {
        console.log("BYPASS ATTEMPT: Session already used");
        return res.redirect("/?error=already_used");
      }

      // Validasi 5: Session tidak expired (5 menit)
      if (Date.now() - session.created_at > 5 * 60 * 1000) {
        console.log("BYPASS ATTEMPT: Session expired");
        return res.redirect("/?error=session_expired");
      }

      // Validasi 6: IP harus sama (opsional, untuk keamanan ekstra)
      if (session.ip_address !== ip) {
        console.log("BYPASS ATTEMPT: IP mismatch", {
          session_ip: session.ip_address,
          current_ip: ip
        });
        // Bisa di-uncomment jika ingin strict
        // return res.redirect("/?error=ip_mismatch");
      }

      // ====================================================
      // 3. AMBIL USER DARI COOKIE
      // ====================================================
      if (!userToken) {
        console.log("No user token found");
        return res.redirect("/?error=login_required");
      }

      const user = verifyUser(userToken);
      if (!user) {
        console.log("Invalid user token");
        return res.redirect("/?error=invalid_session");
      }

      // Validasi 7: Discord ID harus sama dengan session
      if (session.discord_id !== user.id) {
        console.log("BYPASS ATTEMPT: User mismatch", {
          session_user: session.discord_id,
          current_user: user.id
        });
        return res.redirect("/?error=user_mismatch");
      }

      console.log("User authenticated:", user.username);

      // ====================================================
      // 4. TANDAI SESSION SUDAH DIPAKAI
      // ====================================================
      await supabase
        .from("workink_sessions")
        .update({ 
          used: true,
          used_at: Date.now(),
          callback_ip: ip,
          user_agent: req.headers['user-agent'] || 'Unknown'
        })
        .eq("session_id", sessionId);

      // Bersihkan cookie session
      res.setHeader(
        "Set-Cookie",
        `workink_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`
      );

      // ====================================================
      // 5. CEK ATAU BUAT USER DI DATABASE
      // ====================================================
      const ipHash = hashIp(ip);
      const userAgent = req.headers['user-agent'] || 'Unknown';

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
      // 6. CEK APAKAH USER SUDAH PUNYA KEY AKTIF
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
      // 7. GENERATE KEY BARU (2 JAM)
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
        user_agent: userAgent,
        workink_token: session.workink_token
      });

      // ====================================================
      // 8. UPDATE TOTAL KEYS USER
      // ====================================================
      await supabase
        .from("users")
        .update({
          total_keys: (existingUser?.total_keys || 0) + 1
        })
        .eq("discord_id", user.id);

      // ====================================================
      // 9. LOG SUKSES
      // ====================================================
      await supabase.from("verification_logs").insert({
        key_text: key,
        discord_id: user.id,
        ip_address: ip,
        ip_hash: ipHash,
        success: true,
        user_agent: userAgent,
        workink_token: session.workink_token,
        timestamp: Date.now()
      });

      console.log("Key generated successfully, redirecting...");
      
      // ====================================================
      // 10. REDIRECT KE HALAMAN UTAMA DENGAN KEY
      // ====================================================
      return res.redirect(`/?key=${key}&exp=${expiresAt}&source=workink`);

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
