import { supabase } from "../../lib/supabase.js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
    const { key } = req.body;

    if (!key) {
      return res.status(400).json({ error: "Key required" });
    }

    // Ambil data key sebelum delete untuk audit log
    const { data: keyData } = await supabase
      .from("keys")
      .select("*")
      .eq("key", key)
      .single();

    const { error } = await supabase
      .from("keys")
      .delete()
      .eq("key", key);

    if (error) {
      console.error("Delete error:", error);
      return res.status(500).json({ error: "Database error" });
    }

    // Catat audit log
    await supabase.from("audit_logs").insert({
      admin_id: req.headers["x-admin-id"] || "unknown",
      action: "DELETE_KEY",
      target_type: "key",
      target_id: key,
      details: { key_data: keyData },
      ip_address: req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress,
      timestamp: Date.now()
    });

    res.json({ success: true });

  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
