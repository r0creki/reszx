import axios from "axios";
import jwt from "jsonwebtoken";
import qs from "querystring";
import { signUser } from "../lib/auth.js";

export default async function handler(req, res) {
  const code = req.query.code;

  if (!code) {
    return res.redirect("/");
  }

  try {
    // Token exchange
    const tokenResponse = await axios.post(
      "https://discord.com/api/oauth2/token",
      qs.stringify({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: process.env.REDIRECT_URI
      }),
      { 
        headers: { 
          "Content-Type": "application/x-www-form-urlencoded" 
        } 
      }
    );

    // Get user info
    const userResponse = await axios.get(
      "https://discord.com/api/users/@me",
      { 
        headers: { 
          Authorization: `Bearer ${tokenResponse.data.access_token}` 
        } 
      }
    );

    // Sign JWT
    const jwtToken = signUser(userResponse.data);

    // Set cookie
    res.setHeader(
      "Set-Cookie",
      `token=${jwtToken}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
    );

    // Redirect to home
    res.redirect("/");

  } catch (err) {
    console.error("OAuth Error:", err.response?.data || err.message);
    res.redirect("/");
  }
}
