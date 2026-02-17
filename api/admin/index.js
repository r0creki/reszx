import { supabase } from "../../lib/supabase.js";

// ==================== HELPER FUNCTIONS ====================
function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const part = () => Array.from({ length: 5 }, () =>
    chars[Math.floor(Math.random() * chars.length)]
  ).join("");
  return `PEVO-${part()}-${part()}-${part()}`;
}

function parseDuration(input) {
  const num = parseInt(input);
  if (input.endsWith("mo")) return num * 30 * 24 * 60 * 60 * 1000;
  if (input.endsWith("y")) return num * 365 * 24 * 60 * 60 * 1000;
  if (input.endsWith("w")) return num * 7 * 24 * 60 * 60 * 1000;
  if (input.endsWith("d")) return num * 24 * 60 * 60 * 1000;
  if (input.endsWith("h")) return num * 60 * 60 * 1000;
  if (input.endsWith("m")) return num * 60 * 1000;
  return 0;
}

// ==================== MAIN HANDLER ====================
export default async function handler(req, res) {
  // Admin auth untuk semua endpoint
  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { action } = req.query; // ?action=keys, ?action=delete, dll

  try {
    // ========== GET ALL KEYS ==========
    if (req.method === "GET" && (!action || action === "keys")) {
      const { data, error } = await supabase
        .from("keys")
        .select(`
          *,
          users:discord_id (
            discord_username,
            discord_avatar
          )
        `)
        .order("created_at", { ascending: false });

      if (error) throw error;

      const transformed = data.map(k => ({
        key: k.key,
        discordId: k.discord_id,
        discordUsername: k.users?.discord_username,
        hwid: k.hwid ? k.hwid.substring(0, 16) + '...' : null,
        expiresAt: k.expires_at,
        failedAttempts: k.failed_attempts,
        label: k.label,
        createdAt: k.created_at,
        used: k.used,
        banned: k.banned,
        ip_address: k.ip_address,
        last_used: k.last_used_at,
        user_agent: k.user_agent
      }));

      return res.json(transformed);
    }

    // ========== GENERATE KEY ==========
    if (req.method === "POST" && action === "generate") {
      const { duration, label, quantity = 1 } = req.body;

      if (!duration) {
        return res.status(400).json({ error: "Duration required" });
      }

      const results = [];
      for (let i = 0; i < quantity; i++) {
        const key = generateKey();
        const expiresAt = Date.now() + parseDuration(duration);

        const { error } = await supabase.from("keys").insert({
          key,
          expires_at: expiresAt,
          created_at: Date.now(),
          label: label || "Standard",
          used: false,
          failed_attempts: 0
        });

        if (error) throw error;
        results.push({ key, expiresAt });
      }

      return res.json({ 
        success: true, 
        keys: results,
        count: results.length 
      });
    }

    // ========== DELETE KEY ==========
    if (req.method === "POST" && action === "delete") {
      const { key } = req.body;

      if (!key) {
        return res.status(400).json({ error: "Key required" });
      }

      const { error } = await supabase
        .from("keys")
        .delete()
        .eq("key", key);

      if (error) throw error;

      return res.json({ success: true });
    }

    // ========== PURGE EXPIRED ==========
    if (req.method === "POST" && action === "purge") {
      const now = Date.now();

      const { error } = await supabase
        .from("keys")
        .delete()
        .lt("expires_at", now);

      if (error) throw error;

      return res.json({ success: true });
    }

    // ========== EXTEND KEY ==========
    if (req.method === "POST" && action === "extend") {
      const { key, duration } = req.body;

      if (!key || !duration) {
        return res.status(400).json({ error: "Key and duration required" });
      }

      const { data: existing } = await supabase
        .from("keys")
        .select("expires_at")
        .eq("key", key)
        .single();

      if (!existing) {
        return res.status(404).json({ error: "Key not found" });
      }

      const newExpire = existing.expires_at + parseDuration(duration);

      const { error } = await supabase
        .from("keys")
        .update({ expires_at: newExpire })
        .eq("key", key);

      if (error) throw error;

      return res.json({ success: true, new_expires: newExpire });
    }

    // ========== BAN KEY ==========
    if (req.method === "POST" && action === "ban") {
      const { key, reason } = req.body;

      const { error } = await supabase
        .from("keys")
        .update({ 
          banned: true, 
          banned_reason: reason || "Banned by admin",
          banned_at: Date.now()
        })
        .eq("key", key);

      if (error) throw error;

      return res.json({ success: true });
    }

    // ========== UNBAN KEY ==========
    if (req.method === "POST" && action === "unban") {
      const { key } = req.body;

      const { error } = await supabase
        .from("keys")
        .update({ 
          banned: false, 
          banned_reason: null,
          banned_at: null
        })
        .eq("key", key);

      if (error) throw error;

      return res.json({ success: true });
    }

    // ========== STATS ==========
    if (req.method === "GET" && action === "stats") {
      const now = Date.now();

      const { count: total } = await supabase
        .from("keys")
        .select("*", { count: 'exact', head: true });

      const { count: active } = await supabase
        .from("keys")
        .select("*", { count: 'exact', head: true })
        .gt("expires_at", now)
        .eq("banned", false);

      const { count: expired } = await supabase
        .from("keys")
        .select("*", { count: 'exact', head: true })
        .lt("expires_at", now);

      const { count: banned } = await supabase
        .from("keys")
        .select("*", { count: 'exact', head: true })
        .eq("banned", true);

      return res.json({
        total,
        active,
        expired,
        banned
      });
    }

    // Jika action tidak dikenal
    return res.status(400).json({ error: "Invalid action" });

  } catch (error) {
    console.error("Admin API error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}
