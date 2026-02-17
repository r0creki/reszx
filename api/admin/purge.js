import { supabase } from "../../lib/supabase.js";

export default async function handler(req, res) {

  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY)
    return res.status(403).json({ error: "Forbidden" });

  await supabase
    .from("keys")
    .delete()
    .lt("expires_at", Date.now());

  res.json({ success: true });
}
