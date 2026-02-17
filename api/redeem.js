import { supabase } from "../lib/supabase.js";
import { verifyUser } from "../lib/auth.js";

export default async function handler(req, res) {
  // Hanya allow POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const user = verifyUser(token);
    if (!user) {
      return res.status(401).json({ error: "Invalid token" });
    }

    const { key } = req.body;
    if (!key) {
      return res.status(400).json({ error: "Key required" });
    }

    // Cek key
    const { data: keyData, error: fetchError } = await supabase
      .from("keys")
      .select("*")
      .eq("key", key)
      .maybeSingle();

    if (fetchError || !keyData) {
      return res.status(404).json({ error: "Invalid key" });
    }

    // Cek apakah key sudah expired
    if (Date.now() > keyData.expires_at) {
      await supabase.from("keys").delete().eq("key", key);
      return res.status(400).json({ error: "Key expired" });
    }

    // Cek apakah key sudah digunakan
    if (keyData.used) {
      return res.status(400).json({ error: "Key already used" });
    }

    // Cek apakah key sudah punya discord_id
    if (keyData.discord_id) {
      return res.status(400).json({ error: "Key already claimed" });
    }

    // Update key dengan discord_id user
    const { error: updateError } = await supabase
      .from("keys")
      .update({
        discord_id: user.id,
        used: true
      })
      .eq("key", key);

    if (updateError) {
      console.error("Update error:", updateError);
      return res.status(500).json({ error: "Failed to redeem key" });
    }

    res.json({ 
      success: true,
      message: "Key redeemed successfully" 
    });

  } catch (err) {
    console.error("Redeem error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
