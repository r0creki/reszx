export default function handler(req, res) {

  res.setHeader("Set-Cookie", [
    "token=; HttpOnly; Path=/; Max-Age=0; Secure; SameSite=Lax",
    "workink_pass=; HttpOnly; Path=/; Max-Age=0; Secure; SameSite=Lax"
  ]);

  res.status(200).json({ success: true });
}
