import { supabase } from "../lib/supabase.js";
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

async function getIpInfo(ip) {
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    return response.data;
  } catch (error) {
    return null;
  }
}

async function sendToWebhook(type, data) {
  if (!process.env.WEBHOOK_DISCORD) return;

  const colors = {
    success: 0x00ff00,
    warning: 0xffaa00,
    error: 0xff0000,
    info: 0x0099ff
  };

  const embeds = [{
    title: data.title || `${type.toUpperCase()} - Pevolution`,
    color: colors[type] || colors.info,
    timestamp: new Date().toISOString(),
    fields: Object.entries(data.fields || {}).map(([name, value]) => ({
      name,
      value: String(value).substring(0, 1024),
      inline: true
    })),
    footer: {
      text: `Pevolution Logger`
    }
  }];

  try {
    await axios.post(process.env.WEBHOOK_DISCORD, { embeds });
  } catch (error) {
    console.error("Webhook error:", error);
  }
}

export default async function handler(req, res) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                   req.headers['x-real-ip'] || 
                   req.socket.remoteAddress || 
                   'Unknown';

  console.log(`=== INCOMING REQUEST ===`);
  console.log("URL:", req.url);
  console.log("IP:", clientIp);
  console.log("Cookies:", req.cookies);

  // ========== DISCORD OAUTH CALLBACK ==========
  if (req.url.startsWith('/api/callback')) {
    const { code } = req.query;
    console.log("Discord OAuth callback with code:", code ? "YES" : "NO");
    
    if (!code) {
      return res.redirect("/");
    }

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

      const user = userResponse.data;
      console.log("Discord user:", user.username, user.id);

      const ipInfo = await getIpInfo(clientIp);

      const jwtToken = jwt.sign({
        id: user.id,
        username: user.username,
        avatar: user.avatar
      }, process.env.JWT_SECRET, { expiresIn: "7d" });

      await supabase.from("users").upsert({
        discord_id: user.id,
        discord_username: user.username,
        discord_avatar: user.avatar,
        last_login: Date.now(),
        last_ip: clientIp,
        ip_info: ipInfo,
        user_agent: req.headers['user-agent']
      }, { onConflict: 'discord_id' });

      await sendToWebhook("success", {
        title: "✅ User Logged In",
        fields: {
          "User": `${user.username} (${user.id})`,
          "IP Address": clientIp,
          "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
          "🏢 ISP": ipInfo?.isp || 'Unknown'
        }
      });

      res.setHeader("Set-Cookie", `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`);
      console.log("Login successful, redirecting to /");
      return res.redirect("/");
      
    } catch (error) {
      console.error("Discord OAuth error:", error);
      return res.redirect("/");
    }
  }

  // ========== REGULAR API ROUTES ==========
  const { action } = req.query;

  try {
    // ========== LOGIN ==========
    if (action === "login") {
      const params = new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        redirect_uri: process.env.REDIRECT_URI,
        response_type: "code",
        scope: "identify"
      });
      
      await sendToWebhook("info", {
        title: "🔐 Login Attempt",
        fields: {
          "IP Address": clientIp,
          "User Agent": req.headers['user-agent'] || 'Unknown'
        }
      });
      
      return res.redirect(`https://discord.com/oauth2/authorize?${params}`);
    }

    // ========== ME ==========
    if (action === "me") {
      const token = req.cookies.token;
      if (!token) return res.json({ authenticated: false });

      try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        
        const { data: activeKey } = await supabase
          .from("keys")
          .select("key, expires_at, label")
          .eq("discord_id", user.id)
          .gt("expires_at", Date.now())
          .maybeSingle();

        return res.json({
          authenticated: true,
          user: {
            id: user.id,
            username: user.username,
            avatar: user.avatar,
            hasKey: !!activeKey,
            key: activeKey?.key || null,
            expires: activeKey?.expires_at || null,
            label: activeKey?.label || "Free"
          }
        });
      } catch {
        return res.json({ authenticated: false });
      }
    }

    // ========== WORKINK - Generate Link ==========
    if (action === "workink") {
      const token = req.cookies.token;
      if (!token) return res.status(401).json({ error: "Unauthorized" });

      try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        const ipInfo = await getIpInfo(clientIp);
        
        const randomId = Math.random().toString(36).substring(2, 10);
        const workinkUrl = `https://work.ink/2jhr/pevolution-key?uid=${randomId}&discord=${user.id}`;

        await sendToWebhook("info", {
          title: "🔄 Work.ink Link Generated",
          fields: {
            "User": `${user.username} (${user.id})`,
            "IP Address": clientIp,
            "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown'
          }
        });

        return res.json({
          success: true,
          workink_url: workinkUrl
        });
      } catch {
        return res.status(401).json({ error: "Invalid token" });
      }
    }

    // ========== FREE-KEY - VALIDATION ENDPOINT (FIXED) ==========
    if (action === "free-key") {
      const { token, discord } = req.query;
      
      console.log("=== FREE-KEY VALIDATION ===");
      console.log("Token:", token);
      console.log("Discord:", discord);
      
      if (!token || !discord) {
        console.log("ERROR: Missing token or discord");
        return res.status(400).json({ valid: false });
      }

      // SELALU return true untuk Work.ink
      // Keamanan ada di callback (cek cookie & discord ID)
      console.log("Validation successful, returning true");
      
      return res.json({ valid: true });
    }

    // ========== WORKINK CALLBACK - GENERATE KEY ==========
    if (action === "callback") {
      console.log("========== WORKINK CALLBACK ==========");
      console.log("Query params:", req.query);
      console.log("Cookies:", req.cookies);
      
      const { uid, discord } = req.query;
      const userToken = req.cookies.token;
      
      console.log("UID:", uid);
      console.log("Discord param:", discord);
      console.log("User token exists:", !!userToken);

      if (!uid || !discord) {
        console.log("ERROR: Missing uid or discord");
        return res.redirect("/?error=invalid_params");
      }

      if (!userToken) {
        console.log("ERROR: No user token");
        return res.redirect("/?error=login_required");
      }

      try {
        const user = jwt.verify(userToken, process.env.JWT_SECRET);
        console.log("User from token:", { id: user.id, username: user.username });
        
        // Validasi discord ID harus sama dengan token
        if (user.id !== discord) {
          console.log("ERROR: User mismatch", { tokenUser: user.id, discordParam: discord });
          return res.redirect("/?error=user_mismatch");
        }
        console.log("Discord ID match");

        // CEK APAKAH SUDAH PUNYA KEY AKTIF
        console.log("Checking existing key for user:", user.id);
        const { data: existingKey } = await supabase
          .from("keys")
          .select("*")
          .eq("discord_id", user.id)
          .gt("expires_at", Date.now())
          .maybeSingle();

        if (existingKey) {
          console.log("User already has key:", existingKey.key);
          return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
        }

        // GENERATE KEY BARU
        console.log("Generating new key...");
        const key = generateKey();
        const expiresAt = Date.now() + 7200000; // 2 jam
        console.log("New key:", key);

        const ipInfo = await getIpInfo(clientIp);

        // SIMPAN KEY KE DATABASE
        const { error: insertError } = await supabase.from("keys").insert({
          key: key,
          discord_id: user.id,
          expires_at: expiresAt,
          created_at: Date.now(),
          used: true,
          ip_address: clientIp,
          ip_info: ipInfo,
          user_agent: req.headers['user-agent']
        });

        if (insertError) {
          console.error("Error saving key:", insertError);
          return res.redirect("/?error=key_generation_failed");
        }

        console.log("Key saved to database");

        // KIRIM WEBHOOK
        await sendToWebhook("success", {
          title: "✅ New Key Generated",
          fields: {
            "User": `${user.username} (${user.id})`,
            "Key": key,
            "Expires": new Date(expiresAt).toLocaleString(),
            "IP Address": clientIp,
            "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
            "🏢 ISP": ipInfo?.isp || 'Unknown',
            "🌐 Timezone": ipInfo?.timezone || 'Unknown',
            "💻 User Agent": req.headers['user-agent'] || 'Unknown'
          }
        });

        console.log("Redirecting with key:", `/?key=${key}&exp=${expiresAt}`);
        return res.redirect(`/?key=${key}&exp=${expiresAt}`);

      } catch (error) {
        console.error("Workink callback error:", error);
        return res.redirect("/?error=server_error");
      }
    }

    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
    console.error("SERVER ERROR:", error);
    await sendToWebhook("error", {
      title: "❌ Server Error",
      fields: {
        "IP Address": clientIp,
        "Error": error.message
      }
    });
    return res.status(500).json({ error: "Internal server error" });
  }
}
