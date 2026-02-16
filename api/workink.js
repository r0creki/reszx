import jwt from "jsonwebtoken";

export default function handler(req, res) {

  const token = jwt.sign(
    { passed: true },
    process.env.JWT_SECRET,
    { expiresIn: "2m" }
  );

  res.setHeader(
    "Set-Cookie",
    `workink_pass=${token}; HttpOnly; Path=/; Max-Age=120`
  );

  res.redirect("/?generate=free");
}
