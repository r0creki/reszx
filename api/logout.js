export default function handler(req, res) {

  res.setHeader("Set-Cookie", [
    "token=; HttpOnly; Path=/; Max-Age=0",
    "workink_pass=; HttpOnly; Path=/; Max-Age=0"
  ]);

  res.status(200).json({ success: true });
}
