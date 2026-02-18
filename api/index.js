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

async function getIpInfo(ip) {
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,mobile,proxy,hosting`);
    if (response.data.status === 'success') return response.data;
    return null;
  } catch { 
    return null; 
  }
}

async function sendToWebhook(type, data) {
  if (!process.env.WEBHOOK_DISCORD) {
    console.log("Webhook URL not configured");
    return;
  }

  try {
    new URL(process.env.WEBHOOK_DISCORD);
  } catch (e) {
    console.error("Invalid webhook URL");
    return;
  }

  const colors = {
    success: 0x00ff00,
    warning: 0xffaa00,
    error: 0xff0000,
    info: 0x0099ff
  };

  const embed = {
    title: data.title || `${type.toUpperCase()} - Pevolution`,
    color: colors[type] || colors.info,
    timestamp: new Date().toISOString(),
    fields: [],
    footer: { text: `Pevolution Logger` }
  };

  if (data.fields) {
    for (const [name, value] of Object.entries(data.fields)) {
      embed.fields.push({
        name: name,
        value: String(value).substring(0, 1024),
        inline: true
      });
    }
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    await fetch(process.env.WEBHOOK_DISCORD, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);
  } catch (error) {
    // Silent fail - jangan ganggu response utama
  }
}

export default async function handler(req, res) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'Unknown';

  // ========== DISCORD OAUTH CALLBACK ==========
  if (req.url.startsWith('/api/callback')) {
    const { code } = req.query;
    if (!code) return res.redirect("/");

    try {
      const tokenResponse = await axios.post("https://discord.com/api/oauth2/token",
        qs.stringify({
          client_id: process.env.CLIENT_ID,
          client_secret: process.env.CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: process.env.REDIRECT_URI
        }), { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      const userResponse = await axios.get("https://discord.com/api/users/@me",
        { headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` } }
      );

      const user = userResponse.data;
      const ipInfo = await getIpInfo(clientIp);
      
      const now = new Date();
      const today = now.toISOString().split('T')[0];
      const time = now.toTimeString().split(' ')[0];

      const { data: existingUser } = await supabase
        .from("users")
        .select("login_count")
        .eq("discord_id", user.id)
        .maybeSingle();

      if (existingUser) {
        await supabase
          .from("users")
          .update({
            discord_username: user.username,
            discord_avatar: user.avatar,
            last_ip: clientIp,
            ip_country: ipInfo?.country,
            ip_region: ipInfo?.regionName,
            ip_city: ipInfo?.city,
            ip_isp: ipInfo?.isp,
            ip_asn: ipInfo?.as,
            last_login_date: today,
            last_login_time: time,
            user_agent: req.headers['user-agent'],
            login_count: (existingUser.login_count || 0) + 1
          })
          .eq("discord_id", user.id);
      } else {
        await supabase
          .from("users")
          .insert({
            discord_id: user.id,
            discord_username: user.username,
            discord_avatar: user.avatar,
            last_ip: clientIp,
            ip_country: ipInfo?.country,
            ip_region: ipInfo?.regionName,
            ip_city: ipInfo?.city,
            ip_isp: ipInfo?.isp,
            ip_asn: ipInfo?.as,
            last_login_date: today,
            last_login_time: time,
            user_agent: req.headers['user-agent'],
            login_count: 1
          });
      }

      sendToWebhook("success", {
        title: "✅ User Logged In",
        fields: {
          "User": `${user.username} (${user.id})`,
          "IP Address": clientIp,
          "Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
          "ISP": ipInfo?.isp || 'Unknown',
          "Date": today,
          "Time": time
        }
      }).catch(() => {});

      const jwtToken = signUser(user);
      res.setHeader("Set-Cookie", `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`);
      return res.redirect("/");
      
    } catch (error) {
      return res.redirect("/");
    }
  }

  const { action } = req.query;

  try {
    if (action === "login") {
      const params = new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        redirect_uri: process.env.REDIRECT_URI,
        response_type: "code",
        scope: "identify"
      });
      
      sendToWebhook("info", {
        title: "🔐 Login Attempt",
        fields: {
          "IP Address": clientIp,
          "User Agent": req.headers['user-agent'] || 'Unknown'
        }
      }).catch(() => {});

      return res.redirect(`https://discord.com/oauth2/authorize?${params}`);
    }

    if (action === "me") {
      const token = req.cookies.token;
      if (!token) return res.json({ authenticated: false });
      
      const user = verifyUser(token);
      if (!user) return res.json({ authenticated: false });

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
    }

    if (action === "workink") {
      const token = req.cookies.token;
      if (!token) return res.status(401).json({ error: "Unauthorized" });
      
      const user = verifyUser(token);
      if (!user) return res.status(401).json({ error: "Invalid token" });

      const randomId = Math.random().toString(36).substring(2, 10);
      
      sendToWebhook("info", {
        title: "🔄 Work.ink Link Generated",
        fields: {
          "User": `${user.username} (${user.id})`,
          "IP Address": clientIp,
          "UID": randomId
        }
      }).catch(() => {});

      return res.json({ 
        success: true, 
        workink_url: `https://work.ink/2jhr/pevolution-key?uid=${randomId}` 
      });
    }

    if (action === "free-key") {
      const { token, discord } = req.query;
      if (!token || !discord) return res.status(400).json({ valid: false });
      return res.json({ valid: true });
    }

    // ========== WORKINK CALLBACK ==========
    if (action === "callback") {
      console.log("========== WORKINK CALLBACK ==========");
      
      const { uid } = req.query;
      const userToken = req.cookies.token;
      
      if (!uid) return res.redirect("/?error=invalid_params");
      if (!userToken) return res.redirect("/?error=login_required");

      const user = verifyUser(userToken);
      if (!user) return res.redirect("/?error=invalid_token");
      
      console.log("User:", user.id, user.username);

      const { data: existingUser } = await supabase
        .from("users")
        .select("*")
        .eq("discord_id", user.id)
        .maybeSingle();

      if (!existingUser) {
        console.log("User not found, creating...");
        await supabase.from("users").insert({
          discord_id: user.id,
          discord_username: user.username,
          discord_avatar: user.avatar,
          last_ip: clientIp,
          last_login_date: new Date().toISOString().split('T')[0],
          last_login_time: new Date().toTimeString().split(' ')[0],
          user_agent: req.headers['user-agent'],
          login_count: 1
        });
      }

      const { data: existingKey } = await supabase
        .from("keys")
        .select("*")
        .eq("discord_id", user.id)
        .gt("expires_at", Date.now())
        .maybeSingle();

      if (existingKey) {
        console.log("User already has key:", existingKey.key);
        
        sendToWebhook("info", {
          title: "🔄 Existing Key Used",
          fields: {
            "User": `${user.username} (${user.id})`,
            "Key": existingKey.key,
            "Expires": new Date(existingKey.expires_at).toLocaleString(),
            "IP": clientIp,
            "UID": uid
          }
        }).catch(() => {});

        return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
      }

      const key = generateKey();
      const expiresAt = Date.now() + 7200000;
      console.log("New key:", key);

      const ipInfo = await getIpInfo(clientIp);

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
        console.error("Insert error:", insertError);
        return res.redirect("/?error=key_generation_failed");
      }

      if (existingUser) {
        await supabase
          .from("users")
          .update({ total_keys: (existingUser.total_keys || 0) + 1 })
          .eq("discord_id", user.id);
      } else {
        await supabase
          .from("users")
          .update({ total_keys: 1 })
          .eq("discord_id", user.id);
      }

      sendToWebhook("success", {
        title: "✅ New Key Generated",
        fields: {
          "User": `${user.username} (${user.id})`,
          "Key": key,
          "Expires": new Date(expiresAt).toLocaleString(),
          "IP Address": clientIp,
          "Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
          "ISP": ipInfo?.isp || 'Unknown',
          "Timezone": ipInfo?.timezone || 'Unknown',
          "Device": ipInfo?.mobile ? 'Mobile' : (ipInfo?.proxy ? 'Proxy' : 'Desktop'),
          "UID": uid
        }
      }).catch(() => {});

      console.log("Redirecting with key");
      return res.redirect(`/?key=${key}&exp=${expiresAt}`);
    }

    // ========== TEST WEBHOOK ==========
    if (action === "test-webhook") {
      sendToWebhook("info", {
        title: "🧪 Test Webhook",
        fields: {
          "Message": "If you see this, webhook works!",
          "Time": new Date().toLocaleString(),
          "IP": clientIp
        }
      }).catch(() => {});

      return res.json({ success: true, message: "Webhook sent (check Discord)" });
    }

    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
    console.error("ERROR:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}
