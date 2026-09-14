const express = require("express");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const UPDATE_TOKEN = process.env.UPDATE_TOKEN;

let currentOdooUrl = null;

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "Odoo Discovery Server",
    odoo_url: currentOdooUrl
  });
});

app.post("/update", (req, res) => {
  const token = req.headers.authorization;

  if (!UPDATE_TOKEN || token !== `Bearer ${UPDATE_TOKEN}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { url } = req.body;

  if (
    typeof url !== "string" ||
    !/^https:\/\/[a-z0-9-]+\.trycloudflare\.com\/?$/i.test(url)
  ) {
    return res.status(400).json({
      error: "Invalid Quick Tunnel URL"
    });
  }

  currentOdooUrl = url.replace(/\/$/, "");

  console.log("Odoo URL updated:", currentOdooUrl);

  res.json({
    success: true,
    url: currentOdooUrl
  });
});

app.get("/url", (req, res) => {
  if (!currentOdooUrl) {
    return res.status(503).json({
      error: "Odoo tunnel unavailable"
    });
  }

  res.json({
    url: currentOdooUrl
  });
});

app.get("/odoo", (req, res) => {
  if (!currentOdooUrl) {
    return res.status(503).send("Odoo tunnel unavailable");
  }

  res.redirect(302, currentOdooUrl);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Discovery Server listening on ${PORT}`);
});