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
      return response.data;
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function sendToWebhook(type, data) {
  if (!process.env.WEBHOOK_DISCORD) return;
  try {
    const colors = { success: 0x00ff00, warning: 0xffaa00, error: 0xff0000, info: 0x0099ff };
    await axios.post(process.env.WEBHOOK_DISCORD, {
      embeds: [{
        title: data.title,
        color: colors[type] || colors.info,
        timestamp: new Date().toISOString(),
        fields: Object.entries(data.fields || {}).map(([n, v]) => ({ name: n, value: String(v).substring(0, 1024), inline: true })),
        footer: { text: `Pevolution Logger` }
      }]
    });
  } catch (error) {}
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

      await supabase.from("users").upsert({
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
        login_count: supabase.raw('COALESCE(login_count, 0) + 1')
      }, { onConflict: 'discord_id' });

      const jwtToken = jwt.sign({ id: user.id, username: user.username, avatar: user.avatar }, process.env.JWT_SECRET, { expiresIn: "7d" });
      res.setHeader("Set-Cookie", `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax; Secure`);
      return res.redirect("/");
      
    } catch (error) {
      return res.redirect("/");
    }
  }

  // ========== REGULAR API ROUTES ==========
  const { action } = req.query;

  try {
    if (action === "login") {
      const params = new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        redirect_uri: process.env.REDIRECT_URI,
        response_type: "code",
        scope: "identify"
      });
      return res.redirect(`https://discord.com/oauth2/authorize?${params}`);
    }

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
      } catch { return res.json({ authenticated: false }); }
    }

    if (action === "workink") {
      const token = req.cookies.token;
      if (!token) return res.status(401).json({ error: "Unauthorized" });
      try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        const randomId = Math.random().toString(36).substring(2, 10);
        return res.json({ success: true, workink_url: `https://work.ink/2jhr/pevolution-key?uid=${randomId}` });
      } catch { return res.status(401).json({ error: "Invalid token" }); }
    }

    if (action === "free-key") {
      const { token, discord } = req.query;
      if (!token || !discord) return res.status(400).json({ valid: false });
      return res.json({ valid: true });
    }

    // ========== WORKINK CALLBACK - FIXED DENGAN ERROR HANDLING DETAIL ==========
    if (action === "callback") {
      console.log("========== WORKINK CALLBACK ==========");
      
      try {
        const { uid } = req.query;
        const userToken = req.cookies.token;
        
        console.log("1. UID:", uid);
        console.log("2. User token exists:", !!userToken);
        console.log("3. Cookies:", req.cookies);

        if (!uid) {
          console.log("ERROR: Missing uid");
          return res.redirect("/?error=invalid_params");
        }

        if (!userToken) {
          console.log("ERROR: No user token");
          return res.redirect("/?error=login_required");
        }

        // VERIFY TOKEN
        let user;
        try {
          user = jwt.verify(userToken, process.env.JWT_SECRET);
          console.log("4. User from token:", { id: user.id, username: user.username });
        } catch (jwtError) {
          console.log("JWT Error:", jwtError.message);
          return res.redirect("/?error=invalid_token");
        }

        // CEK KEY AKTIF
        console.log("5. Checking existing keys for user:", user.id);
        const { data: existingKey, error: keyError } = await supabase
          .from("keys")
          .select("*")
          .eq("discord_id", user.id)
          .gt("expires_at", Date.now())
          .maybeSingle();

        if (keyError) {
          console.log("6. Database error checking key:", keyError);
          return res.redirect("/?error=server_error");
        }

        if (existingKey) {
          console.log("7. User already has key:", existingKey.key);
          return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
        }

        // GENERATE KEY BARU
        console.log("8. Generating new key...");
        const key = generateKey();
        const expiresAt = Date.now() + 7200000;
        console.log("9. New key:", key);

        // GET IP INFO
        console.log("10. Getting IP info for:", clientIp);
        const ipInfo = await getIpInfo(clientIp);
        console.log("11. IP Info:", ipInfo ? "Success" : "Failed");

        // INSERT KEY KE DATABASE
        console.log("12. Inserting key to database...");
        const insertData = {
          key: key,
          discord_id: user.id,
          expires_at: expiresAt,
          created_at: Date.now(),
          used: true,
          ip_address: clientIp,
          user_agent: req.headers['user-agent']
        };

        // Tambah ip_info kalau ada
        if (ipInfo) {
          insertData.ip_info = ipInfo;
        }

        const { error: insertError } = await supabase.from("keys").insert(insertData);

        if (insertError) {
          console.log("13. Insert error:", insertError);
          return res.redirect("/?error=key_generation_failed");
        }
        console.log("13. Key inserted successfully");

        // UPDATE TOTAL KEYS USER
        console.log("14. Updating user total_keys");
        await supabase
          .from("users")
          .update({ total_keys: supabase.raw('COALESCE(total_keys, 0) + 1') })
          .eq("discord_id", user.id);

        // WEBHOOK (optional)
        try {
          await sendToWebhook("success", {
            title: "✅ New Key Generated",
            fields: {
              "User": `${user.username} (${user.id})`,
              "Key": key,
              "Expires": new Date(expiresAt).toLocaleString(),
              "IP": clientIp
            }
          });
        } catch (webhookError) {}

        console.log("15. Redirecting with key");
        return res.redirect(`/?key=${key}&exp=${expiresAt}`);

      } catch (error) {
        console.log("=== CATCH ERROR ===");
        console.log("Error message:", error.message);
        console.log("Error stack:", error.stack);
        return res.redirect("/?error=server_error");
      }
    }

    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
    console.error("SERVER ERROR:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}
