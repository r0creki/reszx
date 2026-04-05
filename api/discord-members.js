import axios from "axios";

export default async function handler(req, res) {
  try {
    const guildId = process.env.DISCORD_GUILD_ID;
    const botToken = process.env.DISCORD_BOT_TOKEN;

    if (!guildId || !botToken) {
      return res.status(500).json({ count: 0, online: 0, error: "Missing env vars" });
    }

    const response = await axios.get(
      `https://discord.com/api/v10/guilds/${guildId}?with_counts=true`,
      { headers: { Authorization: `Bot ${botToken}` } }
    );

    return res.json({
      count: response.data.approximate_member_count,
      online: response.data.approximate_presence_count
    });

  } catch (err) {
    console.error("Discord members error:", err.response?.data || err.message);
    return res.status(500).json({ count: 0, online: 0 });
  }
}
