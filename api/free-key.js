import crypto from "crypto";
import axios from "axios";
import { supabase } from "../lib/supabase.js";
import { verifyUser } from "../lib/auth.js";
import jwt from "jsonwebtoken";

const workinkToken = req.cookies.workink_pass;

if (!workinkToken)
    return res.status(403).json({ error: "Workink required" });

try {
    jwt.verify(workinkToken, process.env.JWT_SECRET);
} catch {
    return res.status(403).json({ error: "Invalid Workink session" });
}

export default async function handler(req, res) {

  if (req.method !== "GET")
    return res.status(405).json({ error: "Method Not Allowed" });

  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const user = verifyUser(token);
    if (!user) return res.status(401).json({ error: "Invalid Token" });

    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0] ||
      req.socket?.remoteAddress ||
      "Unknown";

    // 🔎 cek existing active key
    const { data: existing } = await supabase
      .from("keys")
      .select("*")
      .eq("discord_id", user.id)
      .gt("expires_at", Date.now())
      .single();

    if (existing) {
      return res.json({ key: existing.key });
    }

    // 🔑 generate key
    const key =
      "PEVO-" +
      crypto.randomBytes(6).toString("hex").toUpperCase();

    const expires = Date.now() + 2 * 60 * 60 * 1000;

    await supabase.from("keys").insert({
      key,
      discord_id: user.id,
      expires_at: expires,
      created_at: Date.now(),
      label: "Free",
      failed_attempts: 0,
      used: false
    });

    // 📡 webhook log
    if (process.env.DISCORD_WEBHOOK) {
      await axios.post(process.env.DISCORD_WEBHOOK, {
        embeds: [
          {
            title: "🔑 Free Key Generated",
            color: 5763719,
            fields: [
              { name: "User", value: user.username, inline: true },
              { name: "Discord ID", value: user.id, inline: true },
              { name: "IP", value: ip },
              { name: "Key", value: key }
            ],
            timestamp: new Date().toISOString()
          }
        ]
      });
    }

    res.json({ key });

  } catch (err) {
    console.error("FREE KEY ERROR:", err);
    res.status(500).json({ error: "Server Error" });
  }
}
