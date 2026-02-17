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
  const { action } = req.query;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                   req.headers['x-real-ip'] || 
                   req.socket.remoteAddress || 
                   'Unknown';

  console.log(`=== INCOMING REQUEST: ${action} ===`);
  console.log("IP:", clientIp);
  console.log("Query:", req.query);
  console.log("Cookies:", req.cookies);

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

    // ========== CALLBACK DISCORD ==========
    if (action === "callback") {
      const { code } = req.query;
      console.log("Discord callback with code:", code ? "YES" : "NO");
      
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
            "Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
            "ISP": ipInfo?.isp || 'Unknown'
          }
        });

        res.setHeader("Set-Cookie", `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`);
        console.log("Login successful, redirecting to /");
        return res.redirect("/");
        
      } catch (error) {
        console.error("Discord callback error:", error);
        await sendToWebhook("error", {
          title: "❌ Login Failed",
          fields: {
            "IP Address": clientIp,
            "Error": error.message
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
            "Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
            "Link": workinkUrl
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
      console.log("- IP:", clientIp);
      
      if (!token || !discord) {
        console.log("ERROR: Missing token or discord");
        return res.status(400).json({ valid: false });
      }

      const { data: existing, error: checkError } = await supabase
        .from("workink_valid")
        .select("*")
        .eq("token", token)
        .maybeSingle();

      if (existing) {
        console.log("Token already exists, returning valid");
        return res.json({ valid: true });
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

      console.log("Token saved successfully");
      
      await sendToWebhook("success", {
        title: "✅ Work.ink Token Validated",
        fields: {
          "Discord ID": discord,
          "Token": token,
          "IP Address": clientIp,
          "Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown'
        }
      });

      return res.json({ valid: true });
    }

    // ========== CALLBACK - Generate Key ==========
    if (action === "callback") {
      console.log("=== CALLBACK HIT ===");
      console.log("1. Query params:", req.query);
      console.log("2. Cookies:", req.cookies);
      
      const { uid, discord } = req.query;
      const userToken = req.cookies.token;
      
      console.log("3. UID:", uid);
      console.log("4. Discord param:", discord);
      console.log("5. User token exists:", !!userToken);
      console.log("6. Client IP:", clientIp);

      if (!uid || !discord) {
        console.log("7. ERROR: Missing uid or discord");
        return res.redirect("/");
      }

      if (!userToken) {
        console.log("7. ERROR: No user token");
        return res.redirect("/");
      }

      try {
        const user = jwt.verify(userToken, process.env.JWT_SECRET);
        console.log("8. User from token:", { id: user.id, username: user.username });
        
        if (user.id !== discord) {
          console.log("9. ERROR: User mismatch", { tokenUser: user.id, discordParam: discord });
          return res.redirect("/");
        }
        console.log("9. Discord ID match");

        // CEK SEMUA ENTRI workink_valid
        const { data: allValid, error: allError } = await supabase
          .from("workink_valid")
          .select("*")
          .eq("discord_id", discord)
          .order("created_at", { ascending: false });
          
        console.log("10. All valid entries for this discord:", allValid);

        // CEK VALID WORKINK ENTRY
        console.log("11. Checking workink_valid for discord:", discord);
        const { data: valid, error: validError } = await supabase
          .from("workink_valid")
          .select("*")
          .eq("discord_id", discord)
          .eq("used", false)
          .gt("created_at", Date.now() - 600000) // 10 menit
          .order("created_at", { ascending: false })
          .limit(1)
          .maybeSingle();

        console.log("12. Valid entry found:", valid);
        console.log("12a. Valid error:", validError);

        if (!valid) {
          console.log("13. ERROR: No valid workink entry");
          return res.redirect("/");
        }

        // Tandai sudah dipakai
        const { error: updateError } = await supabase
          .from("workink_valid")
          .update({ used: true, used_at: Date.now() })
          .eq("id", valid.id);
          
        console.log("14. Marked valid entry as used, update error:", updateError);

        // CEK KEY AKTIF
        const { data: existingKey, error: keyError } = await supabase
          .from("keys")
          .select("*")
          .eq("discord_id", user.id)
          .gt("expires_at", Date.now())
          .maybeSingle();

        console.log("15. Existing key check:", existingKey, "error:", keyError);

        if (existingKey) {
          console.log("16. User already has key:", existingKey.key);
          return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
        }

        // GENERATE KEY BARU
        const key = generateKey();
        const expiresAt = Date.now() + 7200000; // 2 jam
        console.log("17. Generated new key:", key);

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
        
        console.log("18. Key saved to database, error:", insertError);

        await sendToWebhook("success", {
          title: "✅ New Key Generated",
          fields: {
            "User": `${user.username} (${user.id})`,
            "Key": key,
            "Expires": new Date(expiresAt).toLocaleString(),
            "IP Address": clientIp,
            "Location": ipInfo ? `${ipInfo.city || 'Unknown'}, ${ipInfo.country || 'Unknown'}` : 'Unknown',
            "ISP": ipInfo?.isp || 'Unknown',
            "Coordinates": ipInfo ? `${ipInfo.lat}, ${ipInfo.lon}` : 'Unknown',
            "Timezone": ipInfo?.timezone || 'Unknown',
            "User Agent": req.headers['user-agent'] || 'Unknown'
          }
        });
        console.log("19. Webhook sent, redirecting with key");

        return res.redirect(`/?key=${key}&exp=${expiresAt}`);

      } catch (error) {
        console.log("18. CATCH ERROR:", error);
        return res.redirect("/");
      }
    }

    // ========== DEBUG - LIHAT WORKINK VALID ==========
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
        
      const { data: users } = await supabase
        .from("users")
        .select("*")
        .limit(20);
        
      return res.json({
        workink_valid: valid,
        recent_keys: keys,
        users: users,
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
