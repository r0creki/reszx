import { supabase } from "../lib/supabase.js";
import { verifyUser } from "../lib/auth.js";
import crypto from "crypto"; // <-- PERBAIKAN: import crypto, bukan require

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

export default async function handler(req, res) {
  const { token } = req.query;
  
  console.log("Workink callback with token:", token);

  // Cek token
  if (!token) {
    return res.redirect("/?error=no_token");
  }

  // Validasi format token (optional)
  if (!token.startsWith("pevolution-")) {
    return res.redirect("/?error=invalid_token");
  }

  try {
    // Dapatkan IP user
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
               req.socket.remoteAddress || 
               'Unknown';
    
    const ipHash = hashIp(ip);
    const userAgent = req.headers['user-agent'] || 'Unknown';

    // Ambil user dari cookie
    const userToken = req.cookies.token;
    if (!userToken) {
      return res.redirect("/?error=login_required");
    }

    const user = verifyUser(userToken);
    if (!user) {
      return res.redirect("/?error=invalid_session");
    }

    // CEK USER DI DATABASE
    const { data: existingUser } = await supabase
      .from("users")
      .select("*")
      .eq("discord_id", user.id)
      .maybeSingle();

    if (!existingUser) {
      // Insert user baru
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
      // Update user
      await supabase
        .from("users")
        .update({
          discord_username: user.username,
          discord_avatar: user.avatar,
          last_login_at: Date.now(),
          last_login_ip: ip,
          login_count: existingUser.login_count + 1
        })
        .eq("discord_id", user.id);
    }

    // CEK IP BLACKLIST
    const { data: blacklisted } = await supabase
      .from("ip_blacklist")
      .select("*")
      .eq("ip_address", ip)
      .maybeSingle();

    if (blacklisted) {
      return res.redirect("/?error=ip_banned");
    }

    // CEK TOKEN SUDAH DIPAKAI
    const { data: existingToken } = await supabase
      .from("workink_tokens")
      .select("*")
      .eq("token", token)
      .maybeSingle();

    if (existingToken) {
      // Log percobaan token ulang
      await supabase.from("verification_logs").insert({
        key_text: "WORKINK_TOKEN_REUSE",
        discord_id: user.id,
        ip_address: ip,
        ip_hash: ipHash,
        success: false,
        error_reason: "Token already used",
        user_agent: userAgent,
        timestamp: Date.now()
      });

      return res.redirect("/?error=token_used");
    }

    // SIMPAN TOKEN
    await supabase.from("workink_tokens").insert({
      token,
      discord_id: user.id,
      ip_address: ip,
      ip_hash: ipHash,
      used: true,
      used_at: Date.now(),
      user_agent: userAgent
    });

    // CEK KEY AKTIF
    const { data: existingKey } = await supabase
      .from("keys")
      .select("*")
      .eq("discord_id", user.id)
      .gt("expires_at", Date.now())
      .eq("banned", false)
      .maybeSingle();

    if (existingKey) {
      // Update last used
      await supabase
        .from("keys")
        .update({
          last_used_at: Date.now(),
          last_verified_at: Date.now(),
          ip_address: ip,
          user_agent: userAgent
        })
        .eq("id", existingKey.id);

      return res.redirect(`/?key=${existingKey.key}&exp=${existingKey.expires_at}`);
    }

    // GENERATE KEY BARU (2 JAM)
    const key = generateKey();
    const expiresAt = Date.now() + 2 * 60 * 60 * 1000;

    // SIMPAN KEY
    const { data: newKey } = await supabase.from("keys").insert({
      key,
      discord_id: user.id,
      expires_at: expiresAt,
      created_at: Date.now(),
      label: "Free",
      used: true,
      ip_address: ip,
      ip_hash: ipHash,
      last_used_at: Date.now(),
      last_verified_at: Date.now(),
      user_agent: userAgent,
      device_info: userAgent
    }).select().single();

    // LOG SUKSES
    await supabase.from("verification_logs").insert({
      key_id: newKey.id,
      key_text: key,
      discord_id: user.id,
      ip_address: ip,
      ip_hash: ipHash,
      success: true,
      user_agent: userAgent,
      timestamp: Date.now()
    });

    // UPDATE TOTAL KEYS USER
    await supabase
      .from("users")
      .update({
        total_keys: supabase.raw('total_keys + 1')
      })
      .eq("discord_id", user.id);

    // REDIRECT DENGAN KEY
    res.redirect(`/?key=${key}&exp=${expiresAt}`);

  } catch (error) {
    console.error("Free key error:", error);
    
    // Log error
    await supabase.from("verification_logs").insert({
      error_reason: error.message,
      success: false,
      timestamp: Date.now()
    }).catch(() => {});
    
    res.redirect("/?error=server_error");
  }
}
