import axios from "axios";
import jwt from "jsonwebtoken";
import qs from "querystring";

export default async function handler(req, res) {
  const code = req.query.code;

  try {
    const token = await axios.post(
      "https://discord.com/api/oauth2/token",
      qs.stringify({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: process.env.REDIRECT_URI
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const user = await axios.get(
      "https://discord.com/api/users/@me",
      { headers: { Authorization: `Bearer ${token.data.access_token}` } }
    );

    const jwtToken = jwt.sign(user.data, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });

    res.setHeader(
      "Set-Cookie",
      `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800`
    );

    res.redirect("/");
  } catch (err) {
    console.error("OAuth Error:", err);
    res.redirect("/");
  }
}
