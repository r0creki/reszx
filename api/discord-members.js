import axios from "axios";

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET");

  try {
    const guildId = process.env.DISCORD_GUILD_ID;
    const botToken = process.env.DISCORD_BOT_TOKEN;

    if (!guildId || !botToken) {
      console.error("Missing DISCORD_GUILD_ID or DISCORD_BOT_TOKEN");
      return res.status(500).json({ count: 0, online: 0, error: "Missing env vars" });
    }

    const response = await axios.get(
      `https://discord.com/api/v10/guilds/${guildId}?with_counts=true`,
      {
        headers: {
          Authorization: `Bot ${botToken}`,
          "Content-Type": "application/json"
        }
      }
    );

    const { approximate_member_count, approximate_presence_count, name } = response.data;

    return res.json({
      count: approximate_member_count || 0,
      online: approximate_presence_count || 0,
      name: name || ""
    });

  } catch (err) {
    console.error("Discord members error:", err.response?.data || err.message);
    return res.status(500).json({ count: 0, online: 0, error: "Failed to fetch" });
  }
}
