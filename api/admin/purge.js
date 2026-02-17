import { supabase } from "../../lib/supabase.js";

export default async function handler(req, res) {
  // Hanya allow POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  // Admin auth
  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
    const now = Date.now();

    const { error } = await supabase
      .from("keys")
      .delete()
      .lt("expires_at", now);

    if (error) {
      console.error("Purge error:", error);
      return res.status(500).json({ error: "Database error" });
    }

    res.json({ success: true });

  } catch (err) {
    console.error("Purge error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
