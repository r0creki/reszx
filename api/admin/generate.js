console.log("ENV ADMIN:", process.env.ADMIN_KEY);
console.log("HEADER ADMIN:", req.headers["x-admin-key"]);

import { supabase } from "../../lib/supabase.js";

function generateKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  const part = () =>
    Array.from({ length: 5 }, () =>
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

export default async function handler(req, res) {

  // 🔒 Allow POST only
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  // 🔐 Admin auth
  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {

    const { duration, label } = req.body;

    if (!duration) {
      return res.status(400).json({ error: "Duration required" });
    }

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

    if (error) {
      console.error("Supabase Insert Error:", error);
      return res.status(500).json({ error: "Database insert failed" });
    }

    return res.status(200).json({
      success: true,
      key,
      duration,
      label: label || "Standard"
    });

  } catch (err) {
    console.error("Generate Error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}


