export default function handler(req, res) {

  const isProd = process.env.NODE_ENV === "production";

  res.setHeader("Set-Cookie", [
    `token=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${isProd ? "; Secure" : ""}`,
    `workink_pass=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${isProd ? "; Secure" : ""}`
  ]);

  res.status(200).json({ success: true });
}
