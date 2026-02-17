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
  const { action } = req.query; // ?action=login, ?action=me, ?action=free-key, dll

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

      const workinkUrl = `https://work.ink/2jhr/pevolution-{TOKEN}`;

      res.json({
        success: true,
        workink_url: workinkUrl
      });

    } catch (err) {
      console.error("Workink error:", err);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }

  // ========== FREE-KEY (Workink callback) ==========
  if (action === "free-key") {
    const { token } = req.query;

    console.log("========== WORKINK CALLBACK ==========");
  console.log("Raw token from URL:", token);
  console.log("All query params:", req.query);
  console.log("======================================");

    if (!token) {
      return res.redirect("/?error=no_token");
    }

    // Validation to pevolution- format
    if (!token.startsWith("pevolution-")) {
      console.log("Token format invalid. Expected 'pevolution-*' but got:", token);
      return res.redirect("/?error=invalid_token");
    }

    try {
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
                 req.socket.remoteAddress || 
                 'Unknown';

      const ipHash = hashIp(ip);
      const userAgent = req.headers['user-agent'] || 'Unknown';

      const userToken = req.cookies.token;
      if (!userToken) {
        return res.redirect("/?error=login_required");
      }

      const user = verifyUser(userToken);
      if (!user) {
        return res.redirect("/?error=invalid_session");
      }

      // Cek user
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

      // Check if token already used
      const { data: existingToken } = await supabase
        .from("workink_tokens")
        .select("*")
        .eq("token", token)
        .maybeSingle();

      if (existingToken) {
        return res.redirect("/?error=token_used");
      }

      // Save token
      await supabase.from("workink_tokens").insert({
        token,
        discord_id: user.id,
        ip_address: ip,
        ip_hash: ipHash,
        used: true,
        used_at: Date.now(),
        user_agent: userAgent
      });

      // Validate key
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

      // Generate new key (2 hour)
      const key = generateKey();
      const expiresAt = Date.now() + 2 * 60 * 60 * 1000;

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

      return res.redirect(`/?key=${key}&exp=${expiresAt}`);

    } catch (error) {
      console.error("Free key error:", error);
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

  return res.status(400).json({ error: "Invalid action" });
}
