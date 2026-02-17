import jwt from "jsonwebtoken";
import { supabase } from "../lib/supabase.js";

export default async function handler(req, res) {

  const token = req.cookies.token;
  if (!token)
    return res.json({ authenticated: false });

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);

    const { data: activeKey } = await supabase
      .from("keys")
      .select("*")
      .eq("discord_id", user.id)
      .gt("expires_at", Date.now())
      .single();

    res.json({
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar,
        is_admin: user.id === process.env.ADMIN_ID,
        status: activeKey?.label || "Free"
      }
    });

  } catch {
    res.json({ authenticated: false });
  }
}
