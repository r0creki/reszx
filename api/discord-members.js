import axios from "axios";

export default async function handler(req, res) {
  try {
    // Ganti dengan kode invite Discord Anda
    const inviteCode = "BPBvVKK94r"; 
    
    // Panggil API Discord
    const response = await axios.get(`https://discord.com/api/v10/invites/${inviteCode}?with_counts=true`);
    
    // Data dari Discord
    const data = response.data;
    
    // Jumlah member (akurat dari Discord)
    const memberCount = data.approximate_member_count || 0;
    
    // Cache 5 menit biar tidak kena rate limit
    res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate');
    
    // Kirim hanya count
    res.status(200).json({ 
      count: memberCount
    });
    
  } catch (error) {
    console.error("Discord API error:", error.response?.data || error.message);
    
    // Fallback jika API error
    res.status(200).json({ 
      count: 1880 // Angka default
    });
  }
}
