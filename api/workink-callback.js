import jwt from "jsonwebtoken";

export default function handler(req, res) {

  const { done } = req.query;

  // simple validation
  if (!done) {
    return res.status(403).send("Invalid Workink Redirect");
  }

  // bikin session token sementara (5 menit)
  const token = jwt.sign(
    { workink: true },
    process.env.JWT_SECRET,
    { expiresIn: "5m" }
  );

  // set cookie
  res.setHeader("Set-Cookie", `workink_pass=${token}; HttpOnly; Path=/; Secure; SameSite=Lax`);

  // redirect balik ke homepage dengan trigger generate
  res.redirect("/?generate=free");
}

//
