import jwt from "jsonwebtoken";

export default function handler(req, res) {
  const token = req.cookies.token;

  if (!token)
    return res.json({ authenticated: false });

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.json({
  authenticated: true,
  user: {
    id: user.id,
    username: user.username,
    avatar: user.avatar
  }
});
  
  } catch {
    res.json({ authenticated: false });
  }
}
