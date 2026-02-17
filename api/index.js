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

  // ========== DISCORD OAUTH CALLBACK (SPECIAL PATH) ==========
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
          "🏢 ISP": ipInfo?.isp || 'Unknown',
          "💻 User Agent": req.headers['user-agent'] || 'Unknown'
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

    // ========== FREE-KEY - Validation Endpoint ==========
    if (action === "free-key") {
      const { token, discord } = req.query;
      const ipInfo = await getIpInfo(clientIp);
      
      console.log("FREE-KEY VALIDATION");
      console.log("- Token:", token);
      console.log("- Discord:", discord);
      
      if (!token || !discord) {
        return res.status(400).json({ valid: false });
      }

      const { error: insertError } = await supabase.from("workink_valid").insert({
        discord_id: discord,
        token: token,
        ip_address: clientIp,
        ip_info: ipInfo,
        user_agent: req.headers['user-agent'],
        created_at: Date.now(),
        used: false
      });

      if (insertError) {
        console.error("Insert error:", insertError);
        return res.status(500).json({ valid: false });
      }

      await sendToWebhook("success", {
        title: "✅ Work.ink Token Validated",
        fields: {
          "Discord ID": discord,
          "Token": token,
          "IP Address": clientIp,
          "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
          "🏢 ISP": ipInfo?.isp || 'Unknown'
        }
      });

      return res.json({ valid: true });
    }

    // ========== WORKINK CALLBACK - Generate Key ==========
    if (action === "callback") {
      console.log("=== WORKINK CALLBACK ===");
      
      const { uid, discord } = req.query;
      const userToken = req.cookies.token;
      
      console.log("UID:", uid);
      console.log("Discord param:", discord);
      console.log("User token exists:", !!userToken);

      if (!uid || !discord) {
        return res.redirect("/?error=invalid_params");
      }

      if (!userToken) {
        return res.redirect("/?error=login_required");
      }

      try {
        const user = jwt.verify(userToken, process.env.JWT_SECRET);
        
        if (user.id !== discord) {
          console.log("User mismatch", { tokenUser: user.id, discordParam: discord });
          return res.redirect("/?error=user_mismatch");
        }

        const { data: valid } = await supabase
          .from("workink_valid")
          .select("*")
          .eq("discord_id", discord)
          .eq("used", false)
          .gt("created_at", Date.now() - 600000)
          .order("created_at", { ascending: false })
          .limit(1)
          .maybeSingle();

        if (!valid) {
          console.log("No valid workink entry found for discord:", discord);
          return res.redirect("/?error=not_validated");
        }

        await supabase
          .from("workink_valid")
          .update({ used: true, used_at: Date.now() })
          .eq("id", valid.id);

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

        const key = generateKey();
        const expiresAt = Date.now() + 7200000;
        const ipInfo = await getIpInfo(clientIp);

        await supabase.from("keys").insert({
          key: key,
          discord_id: user.id,
          expires_at: expiresAt,
          created_at: Date.now(),
          used: true,
          ip_address: clientIp,
          ip_info: ipInfo,
          user_agent: req.headers['user-agent']
        });

        await sendToWebhook("success", {
          title: "✅ New Key Generated",
          fields: {
            "User": `${user.username} (${user.id})`,
            "Key": `||${key}||`,
            "Expires": new Date(expiresAt).toLocaleString(),
            "IP Address": `||${clientIp}||`,
            "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.regionName || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
            "🗺️ Coordinates": ipInfo ? `${ipInfo.lat}, ${ipInfo.lon}` : 'Unknown',
            "🏢 ISP": ipInfo?.isp || 'Unknown',
            "🏛️ Organization": ipInfo?.org || 'Unknown',
            "🆔 ASN": ipInfo?.as || 'Unknown',
            "🌐 Timezone": ipInfo?.timezone || 'Unknown',
            "📦 ZIP": ipInfo?.zip || 'Unknown',
            "💻 User Agent": req.headers['user-agent'] || 'Unknown'
          }
        });

        console.log("Key generated successfully, redirecting with key");
        return res.redirect(`/?key=${key}&exp=${expiresAt}`);

      } catch (error) {
        console.error("Workink callback error:", error);
        return res.redirect("/?error=server_error");
      }
    }

    // ========== DEBUG ==========
    if (action === "debug-valid") {
      const { data: valid } = await supabase
        .from("workink_valid")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(20);
        
      const { data: keys } = await supabase
        .from("keys")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(20);
        
      return res.json({
        workink_valid: valid,
        recent_keys: keys,
        cookies: req.cookies,
        timestamp: Date.now()
      });
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
