import jwt from "jsonwebtoken";

export function signUser(user) {
  return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "1d" });
}

export function verifyUser(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}
