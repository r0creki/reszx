import { supabase } from "../../lib/supabase.js";

export default async function handler(req, res) {
  // Admin auth
  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
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

    if (error) {
      console.error("Fetch error:", error);
      return res.status(500).json({ error: "Database error" });
    }

    // Transform untuk frontend
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

    res.json(transformed);

  } catch (err) {
    console.error("Keys error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
