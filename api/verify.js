import crypto from "crypto";
import { supabase } from "../lib/supabase.js";

export default async function handler(req, res) {
  const { key, hwid } = req.query;

  if (!key || !hwid)
    return res.json({ valid: false });

  const { data: row } = await supabase
    .from("keys")
    .select("*")
    .eq("key", key)
    .single();

  if (!row)
    return res.json({ valid: false });

  if (Date.now() > row.expires_at) {
    await supabase.from("keys").delete().eq("key", key);
    return res.json({ valid: false });
  }

  if (!row.hwid) {
    await supabase
      .from("keys")
      .update({ hwid, used: true })
      .eq("key", key);
  }

  if (row.hwid && row.hwid !== hwid)
    return res.json({ valid: false });

  const payload = "print('Key Verified Secure!')";

  const signature = crypto
    .createHmac("sha256", process.env.SECRET_SIGNATURE)
    .update(payload)
    .digest("hex");

  res.json({
    valid: true,
    payload,
    signature,
    expiresAt: row.expires_at,
    label: row.label
  });
}
