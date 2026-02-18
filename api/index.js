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
    if (response.data.status === 'success') return response.data;
    return null;
  } catch { return null; }
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

      // UPSERT USER
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
            expires: activeKey?.expires_at || null
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

    // ========== WORKINK CALLBACK - FIXED ==========
    if (action === "callback") {
      console.log("========== WORKINK CALLBACK ==========");
      
      const { uid } = req.query;
      const userToken = req.cookies.token;
      
      if (!uid) return res.redirect("/?error=invalid_params");
      if (!userToken) return res.redirect("/?error=login_required");

      const user = jwt.verify(userToken, process.env.JWT_SECRET);
      console.log("User:", user.id, user.username);

      // CEK ATAU BUAT USER (PASTI ADA)
      const { data: existingUser } = await supabase
        .from("users")
        .select("discord_id")
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

      // CEK KEY AKTIF
      const { data: existingKey } = await supabase
        .from("keys")
        .select("*")
        .eq("discord_id", user.id)
        .gt("expires_at", Date.now())
        .maybeSingle();

      if (existingKey) {
        return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
      }

      // GENERATE KEY BARU
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

      await supabase
        .from("users")
        .update({ total_keys: supabase.raw('COALESCE(total_keys, 0) + 1') })
        .eq("discord_id", user.id);

      return res.redirect(`/?key=${key}&exp=${expiresAt}`);
    }

    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
    console.error("ERROR:", error);
    return res.redirect("/?error=server_error");
  }
}
