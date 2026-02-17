import crypto from "crypto";
import axios from "axios";
import { supabase } from "../lib/supabase.js";
import { verifyUser } from "../lib/auth.js";
import jwt from "jsonwebtoken";

export default async function handler(req, res) {

  // ======================================
  // 🔁 USER DATANG DARI WORKINK
  // ======================================
  if (req.query.from === "workink") {

    try {

      const token = req.cookies.token;
      if (!token)
        return res.redirect("/");

      const user = verifyUser(token);
      if (!user)
        return res.redirect("/");

      // cek existing
      const { data: existing } = await supabase
        .from("keys")
        .select("*")
        .eq("discord_id", user.id)
        .gt("expires_at", Date.now())
        .single();

      if (existing) {
        return res.redirect(`/?key=${existing.key}&exp=${existing.expires_at}`);
      }

      // generate key baru
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

      return res.redirect(`/?key=${key}&exp=${expires}`);

    } catch (err) {
      console.error(err);
      return res.redirect("/");
    }
  }

  // ======================================
  // 🚫 BLOCK DIRECT ACCESS
  // ======================================
  return res.status(403).json({ error: "Workink required" });
}
