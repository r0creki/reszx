import jwt from "jsonwebtoken";
import { verifyUser } from "../lib/auth.js";

export default async function handler(req, res) {
  // Cek user login
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const user = verifyUser(token);
    if (!user) {
      return res.status(401).json({ error: "Invalid token" });
    }

    // Generate random token untuk Workink (format sesuai link Anda)
    // Contoh: pevolution-2026-02-17t043034882z
    const timestamp = new Date().toISOString()
      .replace(/[-:]/g, "")
      .replace(/\.\d+Z$/, "z")
      .toLowerCase();
    
    const randomId = Math.random().toString(36).substring(2, 10);
    
    // Format token: pevolution-TIMESTAMP-RANDOM
    const workinkToken = `pevolution-${timestamp}-${randomId}`;

    // Set cookie untuk tracking (opsional)
    res.setHeader(
      "Set-Cookie",
      `workink_token=${workinkToken}; HttpOnly; Path=/; Max-Age=300; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
    );

    // URL Workink sesuai dengan yang Anda berikan:
    // https://work.ink/2jhr/pevolution-{TOKEN}
    const workinkUrl = `https://work.ink/2jhr/${workinkToken}`;

    res.json({
      success: true,
      workink_url: workinkUrl,
      token: workinkToken,
      expires_in: 300 // 5 menit
    });

  } catch (err) {
    console.error("Workink error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
