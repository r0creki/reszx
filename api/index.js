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

async function getIpInfo(ip) {
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,mobile,proxy,hosting`);
    
    if (response.data.status === 'success') {
      return {
        ip: response.data.query,
        country: response.data.country,
        countryCode: response.data.countryCode,
        region: response.data.region,
        regionName: response.data.regionName,
        city: response.data.city,
        zip: response.data.zip,
        lat: response.data.lat,
        lon: response.data.lon,
        timezone: response.data.timezone,
        isp: response.data.isp,
        org: response.data.org,
        as: response.data.as,
        asname: response.data.asname,
        mobile: response.data.mobile,
        proxy: response.data.proxy,
        hosting: response.data.hosting
      };
    }
    return null;
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
    
    if (!code) return res.redirect("/");

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
      const ipInfo = await getIpInfo(clientIp);
      
      const now = new Date();
      const today = now.toISOString().split('T')[0];
      const time = now.toTimeString().split(' ')[0];

      // SIMPAN USER KE DATABASE
      await supabase.from("users").upsert({
        discord_id: user.id,
        discord_username: user.username,
        discord_avatar: user.avatar,
        discord_email: user.email,
        discord_locale: user.locale,
        discord_verified: user.verified,
        
        last_ip: clientIp,
        ip_country: ipInfo?.country,
        ip_region: ipInfo?.regionName,
        ip_city: ipInfo?.city,
        ip_isp: ipInfo?.isp,
        ip_org: ipInfo?.org,
        ip_asn: ipInfo?.as,
        ip_timezone: ipInfo?.timezone,
        ip_lat: ipInfo?.lat?.toString(),
        ip_lon: ipInfo?.lon?.toString(),
        
        last_login_date: today,
        last_login_time: time,
        user_agent: req.headers['user-agent'],
        login_count: supabase.raw('COALESCE(login_count, 0) + 1')
      }, { onConflict: 'discord_id' });

      // LOG KE AUDIT
      await supabase.from("audit_logs").insert({
        event_type: 'login',
        discord_id: user.id,
        discord_username: user.username,
        ip_address: clientIp,
        ip_country: ipInfo?.country,
        ip_region: ipInfo?.regionName,
        ip_city: ipInfo?.city,
        ip_isp: ipInfo?.isp,
        ip_org: ipInfo?.org,
        ip_asn: ipInfo?.as,
        ip_timezone: ipInfo?.timezone,
        user_agent: req.headers['user-agent'],
        event_date: today,
        event_time: time
      });

      // WEBHOOK LOGIN
      await sendToWebhook("success", {
        title: "✅ User Logged In",
        fields: {
          "User": `${user.username} (${user.id})`,
          "IP Address": clientIp,
          "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.regionName || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
          "🏢 ISP": ipInfo?.isp || 'Unknown',
          "🆔 ASN": ipInfo?.as || 'Unknown',
          "🌐 Timezone": ipInfo?.timezone || 'Unknown',
          "📅 Date": today,
          "⏰ Time": time,
          "📱 Device": ipInfo?.mobile ? 'Mobile' : (ipInfo?.proxy ? 'Proxy' : 'Desktop')
        }
      });

      const jwtToken = jwt.sign({
        id: user.id,
        username: user.username,
        avatar: user.avatar
      }, process.env.JWT_SECRET, { expiresIn: "7d" });

      res.setHeader("Set-Cookie", `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`);
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
        scope: "identify email"
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
        const workinkUrl = `https://work.ink/2jhr/pevolution-key?uid=${randomId}`;

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

    // ========== FREE-KEY - VALIDATION ENDPOINT ==========
    if (action === "free-key") {
      const { token, discord } = req.query;
      
      console.log("=== FREE-KEY VALIDATION ===");
      console.log("Token:", token);
      console.log("Discord:", discord);
      
      if (!token || !discord) {
        return res.status(400).json({ valid: false });
      }

      return res.json({ valid: true });
    }

    // ========== WORKINK CALLBACK - GENERATE KEY (YANG WORK) ==========
    if (action === "callback") {
      console.log("========== WORKINK CALLBACK ==========");
      
      const { uid } = req.query;
      const userToken = req.cookies.token;
      
      console.log("UID from Workink:", uid);
      console.log("User token exists:", !!userToken);

      if (!uid) {
        return res.redirect("/?error=invalid_params");
      }

      if (!userToken) {
        return res.redirect("/?error=login_required");
      }

      try {
        const user = jwt.verify(userToken, process.env.JWT_SECRET);
        console.log("User from cookie:", user.id, user.username);
        
        // CEK KEY AKTIF
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
        const key = generateKey();
        const expiresAt = Date.now() + 7200000; // 2 jam
        console.log("New key:", key);

        const ipInfo = await getIpInfo(clientIp);

        // SIMPAN KEY KE DATABASE
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

        // UPDATE TOTAL KEYS USER
        await supabase
          .from("users")
          .update({ total_keys: supabase.raw('COALESCE(total_keys, 0) + 1') })
          .eq("discord_id", user.id);

        // LOG KE AUDIT
        const now = new Date();
        const today = now.toISOString().split('T')[0];
        const time = now.toTimeString().split(' ')[0];

        await supabase.from("audit_logs").insert({
          event_type: 'key_generate',
          discord_id: user.id,
          discord_username: user.username,
          key_text: key,
          ip_address: clientIp,
          ip_country: ipInfo?.country,
          ip_region: ipInfo?.regionName,
          ip_city: ipInfo?.city,
          ip_isp: ipInfo?.isp,
          ip_org: ipInfo?.org,
          ip_asn: ipInfo?.as,
          ip_timezone: ipInfo?.timezone,
          user_agent: req.headers['user-agent'],
          event_date: today,
          event_time: time,
          details: { uid: uid }
        });

        // WEBHOOK KEY GENERATED
        await sendToWebhook("success", {
          title: "✅ New Key Generated",
          fields: {
            "User": `${user.username} (${user.id})`,
            "Key": key,
            "Expires": new Date(expiresAt).toLocaleString(),
            "IP Address": clientIp,
            "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.regionName || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
            "🏢 ISP": ipInfo?.isp || 'Unknown',
            "🆔 ASN": ipInfo?.as || 'Unknown',
            "🌐 Timezone": ipInfo?.timezone || 'Unknown',
            "📱 Device": ipInfo?.mobile ? 'Mobile' : (ipInfo?.proxy ? 'Proxy' : 'Desktop'),
            "Workink UID": uid
          }
        });

        console.log("Redirecting with key");
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
