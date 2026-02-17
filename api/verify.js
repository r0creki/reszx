import crypto from "crypto";
import { supabase } from "../lib/supabase.js";

function getClientIP(req) {
  return (
    req.headers["x-real-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.headers["x-vercel-forwarded-for"]?.split(",")[0] ||
    req.socket?.remoteAddress ||
    "Unknown"
  );
}

function hashIp(ip) {
  return crypto.createHash('sha256').update(ip).digest('hex');
}

function hashHwid(hwid, secret) {
  return crypto
    .createHash("sha256")
    .update(hwid + secret)
    .digest("hex");
}

export default async function handler(req, res) {
  const { key, hwid } = req.query;

  if (!key || !hwid) {
    return res.json({ valid: false, error: "Missing parameters" });
  }

  const ip = getClientIP(req);
  const ipHash = hashIp(ip);
  const userAgent = req.headers['user-agent'] || 'Unknown';

  try {
    // Cari key
    const { data: row, error } = await supabase
      .from("keys")
      .select("*")
      .eq("key", key)
      .maybeSingle();

    if (error || !row) {
      await supabase.from("verification_logs").insert({
        key_text: key,
        ip_address: ip,
        ip_hash: ipHash,
        success: false,
        error_reason: "Key not found",
        user_agent: userAgent,
        timestamp: Date.now()
      });
      return res.json({ valid: false, error: "Key not found" });
    }

    // Cek banned
    if (row.banned) {
      await supabase.from("verification_logs").insert({
        key_id: row.id,
        key_text: key,
        discord_id: row.discord_id,
        ip_address: ip,
        ip_hash: ipHash,
        success: false,
        error_reason: "Key banned: " + (row.banned_reason || "No reason"),
        user_agent: userAgent,
        timestamp: Date.now()
      });
      return res.json({ valid: false, error: "Key is banned" });
    }

    // Cek expired
    if (Date.now() > row.expires_at) {
      await supabase.from("keys").delete().eq("key", key);
      await supabase.from("verification_logs").insert({
        key_id: row.id,
        key_text: key,
        discord_id: row.discord_id,
        ip_address: ip,
        ip_hash: ipHash,
        success: false,
        error_reason: "Key expired",
        user_agent: userAgent,
        timestamp: Date.now()
      });
      return res.json({ valid: false, error: "Key expired" });
    }

    const hashedHwid = hashHwid(hwid, process.env.SECRET_SIGNATURE || "dev_secret");

    // First time bind
    if (!row.hwid) {
      await supabase
        .from("keys")
        .update({
          hwid: hwid,
          hwid_hash: hashedHwid,
          used: true,
          last_used_at: Date.now(),
          last_verified_at: Date.now(),
          ip_address: ip,
          ip_hash: ipHash,
          user_agent: userAgent
        })
        .eq("key", key);

      await supabase.from("verification_logs").insert({
        key_id: row.id,
        key_text: key,
        discord_id: row.discord_id,
        hwid: hwid,
        hwid_hash: hashedHwid,
        hwid_match: true,
        ip_address: ip,
        ip_hash: ipHash,
        success: true,
        user_agent: userAgent,
        timestamp: Date.now()
      });

      const payload = "print('Key Verified Secure!')";
      const signature = crypto
        .createHmac("sha256", process.env.SECRET_SIGNATURE || "dev_secret")
        .update(payload)
        .digest("hex");

      return res.json({
        valid: true,
        payload,
        signature,
        expiresAt: row.expires_at,
        label: row.label || "Standard"
      });
    }

    // Cek HWID mismatch
    if (row.hwid_hash !== hashedHwid) {
      const newFails = (row.failed_attempts || 0) + 1;

      await supabase.from("verification_logs").insert({
        key_id: row.id,
        key_text: key,
        discord_id: row.discord_id,
        hwid: hwid,
        hwid_hash: hashedHwid,
        hwid_match: false,
        ip_address: ip,
        ip_hash: ipHash,
        success: false,
        error_reason: "HWID mismatch",
        user_agent: userAgent,
        timestamp: Date.now()
      });

      // Jika failed attempts >= 3, hapus key
      if (newFails >= 3) {
        await supabase.from("keys").delete().eq("key", key);
        return res.json({ valid: false, error: "Key deleted - too many failed attempts" });
      }

      // Update failed attempts
      await supabase
        .from("keys")
        .update({
          failed_attempts: newFails,
          last_attempt_ip: ip,
          last_attempt_at: Date.now()
        })
        .eq("key", key);

      return res.json({ valid: false, error: "HWID mismatch" });
    }

    // Reset failed attempts jika sukses
    if (row.failed_attempts > 0) {
      await supabase
        .from("keys")
        .update({ failed_attempts: 0 })
        .eq("key", key);
    }

    // Update last used
    await supabase
      .from("keys")
      .update({
        last_used_at: Date.now(),
        last_verified_at: Date.now(),
        ip_address: ip,
        ip_hash: ipHash,
        user_agent: userAgent
      })
      .eq("key", key);

    // Log sukses
    await supabase.from("verification_logs").insert({
      key_id: row.id,
      key_text: key,
      discord_id: row.discord_id,
      hwid: hwid,
      hwid_hash: hashedHwid,
      hwid_match: true,
      ip_address: ip,
      ip_hash: ipHash,
      success: true,
      user_agent: userAgent,
      timestamp: Date.now()
    });

    const payload = "print('Key Verified Secure!')";
    const signature = crypto
      .createHmac("sha256", process.env.SECRET_SIGNATURE || "dev_secret")
      .update(payload)
      .digest("hex");

    res.json({
      valid: true,
      payload,
      signature,
      expiresAt: row.expires_at,
      label: row.label || "Standard"
    });

  } catch (err) {
    console.error("Verify error:", err);
    
    await supabase.from("verification_logs").insert({
      key_text: key,
      ip_address: ip,
      ip_hash: ipHash,
      success: false,
      error_reason: err.message,
      user_agent: userAgent,
      timestamp: Date.now()
    }).catch(() => {});

    res.json({ valid: false, error: "Server error" });
  }
}
