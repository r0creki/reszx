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
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,mobile,proxy,hosting`);
    
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
      const { error: upsertError } = await supabase.from("users").upsert({
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
        event_time: time,
        details: { login_method: 'discord' }
      });

      // WEBHOOK
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
        
        const today = new Date().toISOString().split('T')[0];
        
        const { data: activeKey } = await supabase
          .from("keys")
          .select("key, expire_date, expire_time, label")
          .eq("discord_id", user.id)
          .gte("expire_date", today)
          .maybeSingle();

        return res.json({
          authenticated: true,
          user: {
            id: user.id,
            username: user.username,
            avatar: user.avatar,
            hasKey: !!activeKey,
            key: activeKey?.key || null,
            expires: activeKey ? `${activeKey.expire_date} ${activeKey.expire_time}` : null,
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
      
      if (!token || !discord) {
        return res.status(400).json({ valid: false });
      }

      return res.json({ valid: true });
    }

    // ========== WORKINK CALLBACK - GENERATE KEY ==========
    if (action === "callback") {
      const { uid } = req.query;
      const userToken = req.cookies.token;

      if (!uid) return res.redirect("/?error=invalid_params");
      if (!userToken) return res.redirect("/?error=login_required");

      try {
        const user = jwt.verify(userToken, process.env.JWT_SECRET);
        const ipInfo = await getIpInfo(clientIp);
        
        const now = new Date();
        const today = now.toISOString().split('T')[0];
        const time = now.toTimeString().split(' ')[0];
        
        const expireDate = new Date(now.getTime() + 2 * 60 * 60 * 1000);
        const expireDateStr = expireDate.toISOString().split('T')[0];
        const expireTimeStr = expireDate.toTimeString().split(' ')[0];

        // CEK KEY AKTIF
        const { data: existingKey } = await supabase
          .from("keys")
          .select("*")
          .eq("discord_id", user.id)
          .gte("expire_date", today)
          .maybeSingle();

        if (existingKey) {
          return res.redirect(`/?key=${existingKey.key}&exp=${expireDate.getTime()}`);
        }

        // GENERATE KEY BARU
        const key = generateKey();

        const { error: insertError } = await supabase.from("keys").insert({
          key: key,
          discord_id: user.id,
          label: "Free",
          
          created_date: today,
          created_time: time,
          expire_date: expireDateStr,
          expire_time: expireTimeStr,
          
          used: true,
          
          ip_address: clientIp,
          ip_country: ipInfo?.country,
          ip_region: ipInfo?.regionName,
          ip_city: ipInfo?.city,
          ip_isp: ipInfo?.isp,
          ip_org: ipInfo?.org,
          ip_asn: ipInfo?.as,
          ip_timezone: ipInfo?.timezone,
          ip_lat: ipInfo?.lat?.toString(),
          ip_lon: ipInfo?.lon?.toString(),
          
          user_agent: req.headers['user-agent']
        });

        if (insertError) {
          return res.redirect("/?error=key_generation_failed");
        }

        // UPDATE TOTAL KEYS USER
        await supabase
          .from("users")
          .update({ total_keys: supabase.raw('COALESCE(total_keys, 0) + 1') })
          .eq("discord_id", user.id);

        // LOG KE AUDIT
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

        // WEBHOOK LENGKAP
        await sendToWebhook("success", {
          title: "✅ New Key Generated",
          fields: {
            "User": `${user.username} (${user.id})`,
            "Key": key,
            "Created": `${today} ${time}`,
            "Expires": `${expireDateStr} ${expireTimeStr}`,
            "IP Address": clientIp,
            "📍 Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.regionName || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
            "🏢 ISP": ipInfo?.isp || 'Unknown',
            "🆔 ASN": ipInfo?.as || 'Unknown',
            "🌐 Timezone": ipInfo?.timezone || 'Unknown',
            "📱 Device": ipInfo?.mobile ? 'Mobile' : (ipInfo?.proxy ? 'Proxy' : 'Desktop'),
            "🆔 UID": uid
          }
        });

        return res.redirect(`/?key=${key}&exp=${expireDate.getTime()}`);

      } catch (error) {
        return res.redirect("/?error=server_error");
      }
    }

    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
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
