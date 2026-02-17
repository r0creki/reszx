import { supabase } from "../lib/supabase.js";
import { verifyUser, signUser } from "../lib/auth.js";
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
    // Gunakan ip-api.com untuk info lengkap (free, no API key)
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
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
      value: String(value),
      inline: true
    })),
    footer: {
      text: `Pevolution Logger • ${new Date().toLocaleString()}`
    }
  }];

  try {
    await axios.post(process.env.WEBHOOK_DISCORD, { embeds });
  } catch (error) {
    console.error("Webhook error:", error);
  }
}

export default async function handler(req, res) {
  const { action } = req.query;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                   req.headers['x-real-ip'] || 
                   req.socket.remoteAddress || 
                   'Unknown';

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
          "User Agent": req.headers['user-agent'] || 'Unknown',
          "Time": new Date().toLocaleString()
        }
      });
      
      return res.redirect(`https://discord.com/oauth2/authorize?${params}`);
    }

    // ========== CALLBACK ==========
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

        const user = userResponse.data;
        const ipInfo = await getIpInfo(clientIp);

        const jwtToken = jwt.sign({
          id: user.id,
          username: user.username,
          avatar: user.avatar
        }, process.env.JWT_SECRET, { expiresIn: "7d" });

        // Simpan user ke database
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
            "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
            "ISP": ipInfo?.isp || 'Unknown',
            "Time": new Date().toLocaleString()
          }
        });

        res.setHeader("Set-Cookie", `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`);
        return res.redirect("/");
        
      } catch (error) {
        await sendToWebhook("error", {
          title: "❌ Login Failed",
          fields: {
            "IP Address": clientIp,
            "Error": error.message,
            "Time": new Date().toLocaleString()
          }
        });
        return res.redirect("/");
      }
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
            "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
            "ISP": ipInfo?.isp || 'Unknown',
            "Link": workinkUrl,
            "Time": new Date().toLocaleString()
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
      
      if (!token || !discord) {
        await sendToWebhook("warning", {
          title: "⚠️ Invalid Work.ink Validation",
          fields: {
            "IP Address": clientIp,
            "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
            "Error": "Missing token or discord",
            "Time": new Date().toLocaleString()
          }
        });
        return res.status(400).json({ valid: false });
      }

      // Simpan ke database
      await supabase.from("workink_valid").insert({
        discord_id: discord,
        token: token,
        ip_address: clientIp,
        ip_info: ipInfo,
        user_agent: req.headers['user-agent'],
        created_at: Date.now(),
        used: false
      });

      await sendToWebhook("success", {
        title: "✅ Work.ink Token Validated",
        fields: {
          "Discord ID": discord,
          "Token": token,
          "IP Address": clientIp,
          "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
          "ISP": ipInfo?.isp || 'Unknown',
          "Time": new Date().toLocaleString()
        }
      });

      return res.json({ valid: true });
    }

    // ========== CALLBACK - Generate Key ==========
    if (action === "callback") {
      const { uid, discord } = req.query;
      const userToken = req.cookies.token;
      const ipInfo = await getIpInfo(clientIp);

      if (!uid || !discord) {
        await sendToWebhook("warning", {
          title: "⚠️ Invalid Callback Params",
          fields: {
            "IP Address": clientIp,
            "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
            "Error": "Missing uid or discord",
            "Time": new Date().toLocaleString()
          }
        });
        return res.redirect("/?error=invalid_params");
      }

      // Cek apakah user sudah login
      if (!userToken) {
        await sendToWebhook("warning", {
          title: "⚠️ Callback Without Login",
          fields: {
            "IP Address": clientIp,
            "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
            "Discord ID": discord,
            "UID": uid,
            "Time": new Date().toLocaleString()
          }
        });
        return res.redirect("/?error=login_required");
      }

      try {
        const user = jwt.verify(userToken, process.env.JWT_SECRET);
        
        // Validasi discord ID harus sama
        if (user.id !== discord) {
          await sendToWebhook("warning", {
            title: "⚠️ User ID Mismatch",
            fields: {
              "IP Address": clientIp,
              "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
              "Token User": user.id,
              "Discord Param": discord,
              "Time": new Date().toLocaleString()
            }
          });
          return res.redirect("/?error=user_mismatch");
        }

        // Cek apakah sudah valid dari Workink (max 10 menit)
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
          await sendToWebhook("warning", {
            title: "⚠️ No Valid Work.ink Entry",
            fields: {
              "User": `${user.username} (${user.id})`,
              "IP Address": clientIp,
              "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
              "Time": new Date().toLocaleString()
            }
          });
          return res.redirect("/?error=not_validated");
        }

        // Tandai sudah dipakai
        await supabase
          .from("workink_valid")
          .update({ used: true, used_at: Date.now() })
          .eq("id", valid.id);

        // Cek apakah sudah punya key aktif
        const { data: existingKey } = await supabase
          .from("keys")
          .select("*")
          .eq("discord_id", user.id)
          .gt("expires_at", Date.now())
          .maybeSingle();

        if (existingKey) {
          await sendToWebhook("info", {
            title: "🔄 Existing Key Used",
            fields: {
              "User": `${user.username} (${user.id})`,
              "Key": existingKey.key,
              "Expires": new Date(existingKey.expires_at).toLocaleString(),
              "IP Address": clientIp,
              "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
              "Time": new Date().toLocaleString()
            }
          });
          return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
        }

        // Generate key baru
        const key = generateKey();
        const expiresAt = Date.now() + 7200000; // 2 jam

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
            "Key": key,
            "Expires": new Date(expiresAt).toLocaleString(),
            "IP Address": clientIp,
            "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
            "ISP": ipInfo?.isp || 'Unknown',
            "Timezone": ipInfo?.timezone || 'Unknown',
            "User Agent": req.headers['user-agent'] || 'Unknown',
            "Time": new Date().toLocaleString()
          }
        });

        return res.redirect(`/?key=${key}&exp=${expiresAt}`);

      } catch (error) {
        await sendToWebhook("error", {
          title: "❌ Key Generation Failed",
          fields: {
            "IP Address": clientIp,
            "Location": ipInfo ? `${ipInfo.city}, ${ipInfo.country}` : 'Unknown',
            "Error": error.message,
            "Time": new Date().toLocaleString()
          }
        });
        return res.redirect("/?error=invalid_token");
      }
    }

    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
    await sendToWebhook("error", {
      title: "❌ Server Error",
      fields: {
        "IP Address": clientIp,
        "Error": error.message,
        "Time": new Date().toLocaleString()
      }
    });
    return res.status(500).json({ error: "Internal server error" });
  }
}
