import { verifyUser } from "../lib/auth.js";
import { supabase } from "../lib/supabase.js";

export default async function handler(req, res) {
  const token = req.cookies.token;

  if (!token) {
    return res.json({ authenticated: false });
  }

  try {
    const user = verifyUser(token);
    
    if (!user) {
      return res.json({ authenticated: false });
    }

    // Ambil data user dari database
    const { data: userData } = await supabase
      .from("users")
      .select("*")
      .eq("discord_id", user.id)
      .maybeSingle();

    // Cek apakah user punya key aktif
    const { data: activeKey } = await supabase
      .from("keys")
      .select("label, expires_at")
      .eq("discord_id", user.id)
      .gt("expires_at", Date.now())
      .eq("banned", false)
      .maybeSingle();

    // Hitung total keys
    const { count: totalKeys } = await supabase
      .from("keys")
      .select("*", { count: 'exact', head: true })
      .eq("discord_id", user.id);

    res.json({
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar,
        discriminator: user.discriminator,
        is_admin: userData?.is_admin || false,
        is_banned: userData?.is_banned || false,
        status: activeKey ? `Premium (${activeKey.label})` : "Free",
        expires_at: activeKey?.expires_at || null,
        total_keys: totalKeys || 0,
        created_at: userData?.created_at || null,
        login_count: userData?.login_count || 0
      }
    });

  } catch (err) {
    console.error("Me error:", err);
    res.json({ authenticated: false });
  }
}
