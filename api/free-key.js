import crypto from "crypto";
import { supabase } from "../lib/supabase.js";
import { verifyUser } from "../lib/auth.js";

function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const part = () =>
    Array.from({ length: 5 }, () =>
      chars[Math.floor(Math.random() * chars.length)]
    ).join("");

  return `PEVO-${part()}-${part()}-${part()}`;
}

export default async function handler(req, res) {

  if (req.query.from !== "workink")
    return res.status(403).json({ error: "Workink required" });

  try {

    const token = req.cookies.token;
    if (!token) return res.redirect("/");

    const user = verifyUser(token);
    if (!user) return res.redirect("/");

    const { data: existing } = await supabase
      .from("keys")
      .select("*")
      .eq("discord_id", user.id)
      .gt("expires_at", Date.now())
      .single();

    if (existing) {
      return res.redirect(`/?key=${existing.key}&exp=${existing.expires_at}`);
    }

    const key = generateKey();
    const expires = Date.now() + 2 * 60 * 60 * 1000;

    await supabase.from("keys").insert({
      key,
      discord_id: user.id,
      expires_at: expires,
      created_at: Date.now(),
      label: "Free",
      used: true
    });

    return res.redirect(`/?key=${key}&exp=${expires}`);

  } catch (err) {
    console.error(err);
    return res.redirect("/");
  }
}
