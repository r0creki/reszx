export default async function handler(req, res) {

    const { game } = req.query;

    // 1️⃣ Cek dulu gamenya ada gak
    const scripts = {
        "violence-district": `
            print("Violence District Loaded")
        `,
        "solo-hunter": `
            print("Solo Hunter Loaded")
        `
    };

    if (!game || !scripts[game]) {
        return res.status(404).send("Not Found");
    }

    // 2️⃣ Baru cek request source
    const secFetchSite = req.headers["sec-fetch-site"];
    const acceptHeader = req.headers["accept"] || "";

    const isBrowser =
        secFetchSite === "same-origin" ||
        acceptHeader.includes("text/html");

    if (isBrowser) {
        return res.status(403).send("Access Denied");
    }

    // 3️⃣ Kirim script
    res.setHeader("Content-Type", "text/plain");
    res.status(200).send(scripts[game]);
}
