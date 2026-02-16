import { supabase } from "../lib/supabase.js";
import { verifyUser } from "../lib/auth.js";

export default async function handler(req, res) {
  try {
    const token = req.cookies.token;
    const user = verifyUser(token);

    const { data: existing } = await supabase
      .from("keys")
      .select("*")
      .eq("discord_id", user.id)
      .gt("expires_at", Date.now())
      .single();

    if (existing)
      return res.json({ key: existing.key });

    const key = "PEVO-" + crypto.randomBytes(6).toString("hex").toUpperCase();

    const expires = Date.now() + 2 * 60 * 60 * 1000;

    await supabase.from("keys").insert({
      key,
      discord_id: user.id,
      expires_at: expires,
      created_at: Date.now(),
      label: "Free"
    });

    res.json({ key });

  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
}
