import crypto from "crypto";
import axios from "axios";
import { supabase } from "../lib/supabase.js";

export default async function handler(req, res) {
  const { key, hwid } = req.query;

  if (!key || !hwid)
    return res.json({ valid: false });

  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket?.remoteAddress ||
    "Unknown";

  const hashedHwid = crypto
    .createHash("sha256")
    .update(hwid + process.env.SECRET_SIGNATURE)
    .digest("hex");

  const { data: row } = await supabase
    .from("keys")
    .select("*")
    .eq("key", key)
    .single();

  if (!row)
    return res.json({ valid: false });

  // expired
  if (Date.now() > row.expires_at) {
    await supabase.from("keys").delete().eq("key", key);
    return res.json({ valid: false });
  }

  // first bind
  if (!row.hwid) {
    await supabase
      .from("keys")
      .update({
        hwid: hashedHwid,
        used: true
      })
      .eq("key", key);

    row.hwid = hashedHwid;
  }

  // mismatch
  if (row.hwid !== hashedHwid) {

    const newFails = (row.failed_attempts || 0) + 1;

    if (newFails >= 3) {
      await supabase.from("keys").delete().eq("key", key);
    } else {
      await supabase
        .from("keys")
        .update({ failed_attempts: newFails })
        .eq("key", key);
    }

    if (process.env.DISCORD_WEBHOOK) {
      await axios.post(process.env.DISCORD_WEBHOOK, {
        embeds: [{
          title: "⚠️ HWID Mismatch",
          color: 15548997,
          fields: [
            { name: "Key", value: key },
            { name: "IP", value: ip },
            { name: "Attempts", value: newFails.toString() }
          ]
        }]
      });
    }

    return res.json({ valid: false });
  }

  // reset fail
  if (row.failed_attempts > 0) {
    await supabase
      .from("keys")
      .update({ failed_attempts: 0 })
      .eq("key", key);
  }

  // success webhook
  if (process.env.DISCORD_WEBHOOK) {
    await axios.post(process.env.DISCORD_WEBHOOK, {
      embeds: [{
        title: "✅ Key Verified",
        color: 5763719,
        fields: [
          { name: "Key", value: key },
          { name: "IP", value: ip },
          { name: "Label", value: row.label }
        ]
      }]
    });
  }

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
