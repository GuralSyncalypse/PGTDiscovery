const express = require("express");
const {
  createProxyMiddleware
} = require("http-proxy-middleware");

const app = express();

const PORT = process.env.PORT || 3000;
const UPDATE_TOKEN = process.env.UPDATE_TOKEN;

// Quick Tunnel hiện tại
let currentOdooUrl = null;

/*
 * Health check
 */
app.get("/_gateway/health", (req, res) => {
  res.json({
    status: "ok",
    upstream: currentOdooUrl ? "configured" : "unavailable"
  });
});

/*
 * API cập nhật Quick Tunnel URL
 *
 * Quan trọng:
 * route này phải nằm TRƯỚC express.json/proxy.
 */
app.post(
  "/_gateway/update",
  express.json(),
  (req, res) => {
    const authorization = req.headers.authorization;

    if (
      !UPDATE_TOKEN ||
      authorization !== `Bearer ${UPDATE_TOKEN}`
    ) {
      return res.status(401).json({
        error: "Unauthorized"
      });
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

    console.log(
      `[gateway] upstream updated: ${currentOdooUrl}`
    );

    return res.json({
      success: true
    });
  }
);

/*
 * Xem trạng thái gateway.
 * Không trả URL thật để tránh leak upstream.
 */
app.get("/_gateway/status", (req, res) => {
  res.json({
    ready: Boolean(currentOdooUrl)
  });
});

/*
 * Reverse proxy Odoo
 */
const odooProxy = createProxyMiddleware({
  router: () => {
    return currentOdooUrl || "http://127.0.0.1:1";
  },

  changeOrigin: true,

  ws: true,

  xfwd: true,

  secure: true,

  proxyTimeout: 120000,
  timeout: 120000,

  on: {
    proxyReq: (proxyReq, req) => {
      /*
       * Odoo phải nghĩ request ban đầu
       * đến từ hostname Render qua HTTPS.
       */
      proxyReq.setHeader(
        "X-Forwarded-Proto",
        "https"
      );

      proxyReq.setHeader(
        "X-Forwarded-Host",
        req.headers.host
      );

      proxyReq.setHeader(
        "X-Forwarded-Port",
        "443"
      );
    },

    proxyReqWs: (proxyReq, req) => {
      proxyReq.setHeader(
        "X-Forwarded-Proto",
        "https"
      );

      proxyReq.setHeader(
        "X-Forwarded-Host",
        req.headers.host
      );
    },

    error: (err, req, res) => {
      console.error(
        "[gateway] proxy error:",
        err.message
      );

      if (
        res &&
        typeof res.status === "function" &&
        !res.headersSent
      ) {
        res.status(502).json({
          error: "Odoo backend unavailable"
        });
      }
    }
  }
});

/*
 * Nếu chưa có Quick Tunnel thì trả 503.
 */
app.use((req, res, next) => {
  if (!currentOdooUrl) {
    return res.status(503).json({
      error: "Odoo tunnel unavailable"
    });
  }

  next();
});

/*
 * TẤT CẢ request còn lại đi tới Odoo.
 */
app.use(odooProxy);

const server = app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Gateway listening on port ${PORT}`
    );
  }
);

/*
 * WebSocket upgrade
 */
server.on("upgrade", odooProxy.upgrade);