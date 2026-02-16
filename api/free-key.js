import crypto from "crypto";
import axios from "axios";
import { supabase } from "../lib/supabase.js";
import { verifyUser } from "../lib/auth.js";
import jwt from "jsonwebtoken";

export default async function handler(req, res) {

  // ==============================
  // MODE 1: WORKINK CALLBACK
  // ==============================

  if (req.query.done === "1") {

    const token = jwt.sign(
      { workink: true },
      process.env.JWT_SECRET,
      { expiresIn: "5m" }
    );

    res.setHeader(
      "Set-Cookie",
      `workink_pass=${token}; HttpOnly; Path=/; Secure; SameSite=Lax`
    );

    return res.redirect("/?generate=free");
  }

  // ==============================
  // MODE 2: GENERATE KEY
  // ==============================

  if (req.method !== "GET")
    return res.status(405).json({ error: "Method Not Allowed" });

  try {

    const loginToken = req.cookies.token;
    if (!loginToken)
      return res.status(401).json({ error: "Unauthorized" });

    const user = verifyUser(loginToken);
    if (!user)
      return res.status(401).json({ error: "Invalid Token" });

    const workinkToken = req.cookies.workink_pass;
    if (!workinkToken)
      return res.status(403).json({ error: "Workink required" });

    try {
      jwt.verify(workinkToken, process.env.JWT_SECRET);
    } catch {
      return res.status(403).json({ error: "Invalid Workink session" });
    }

    const { data: existing } = await supabase
      .from("keys")
      .select("*")
      .eq("discord_id", user.id)
      .gt("expires_at", Date.now())
      .single();

    if (existing)
      return res.json({ key: existing.key });

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

    res.setHeader(
      "Set-Cookie",
      "workink_pass=; HttpOnly; Path=/; Max-Age=0"
    );

    return res.json({ key });

  } catch (err) {
    console.error("FREE KEY ERROR:", err);
    return res.status(500).json({ error: "Server Error" });
  }
}

// test
