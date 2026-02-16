export default function handler(req, res) {

  res.setHeader("Set-Cookie", [
    "token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None",
    "workink_pass=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None"
  ]);

  res.status(200).json({ success: true });
}
