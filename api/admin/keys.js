import { supabase } from "../../lib/supabase.js";

export default async function handler(req, res) {

  if (req.headers["x-admin-key"] !== process.env.ADMIN_KEY)
    return res.status(403).json({ error: "Forbidden" });

  const { data } = await supabase
    .from("keys")
    .select("*")
    .order("created_at", { ascending: false });

  res.json(data);
}
