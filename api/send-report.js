const { createHmac, timingSafeEqual } = require("node:crypto");

const DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const MAX_INIT_DATA_AGE_SECONDS = 24 * 60 * 60;
const ALLOWED_ADMIN_IDS = new Set(["6487334629", "8768210639"]);

function respond(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(payload));
}

function verifyTelegramInitData(rawInitData, botToken) {
  if (typeof rawInitData !== "string" || rawInitData.length === 0 || rawInitData.length > 8192) return null;
  const params = new URLSearchParams(rawInitData);
  const entries = Array.from(params.entries());
  if (new Set(entries.map(([key]) => key)).size !== entries.length) return null;
  const receivedHash = params.get("hash") || "";
  if (!/^[a-f0-9]{64}$/i.test(receivedHash)) return null;

  const dataCheckString = entries
    .filter(([key]) => key !== "hash")
    .sort((first, second) => first[0] < second[0] ? -1 : first[0] > second[0] ? 1 : 0)
    .map(([key, value]) => key + "=" + value)
    .join("\n");
  const secretKey = createHmac("sha256", "WebAppData").update(botToken).digest();
  const expectedHash = createHmac("sha256", secretKey).update(dataCheckString).digest();
  const suppliedHash = Buffer.from(receivedHash, "hex");
  if (suppliedHash.length !== expectedHash.length || !timingSafeEqual(suppliedHash, expectedHash)) return null;

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(authDate) || authDate > now + 60 || now - authDate > MAX_INIT_DATA_AGE_SECONDS) return null;
  try {
    const user = JSON.parse(params.get("user") || "null");
    if (!user || user.id == null) return null;
    return { id: String(user.id) };
  } catch {
    return null;
  }
}

async function readReportBody(req) {
  const declaredLength = Number(req.headers["content-length"] || 0);
  if (declaredLength > MAX_REPORT_BYTES) {
    const error = new Error("Report too large");
    error.code = "REPORT_TOO_LARGE";
    throw error;
  }
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.length;
    if (totalBytes > MAX_REPORT_BYTES) {
      const error = new Error("Report too large");
      error.code = "REPORT_TOO_LARGE";
      throw error;
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

module.exports = async function sendReport(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return respond(res, 405, { code: "METHOD_NOT_ALLOWED" });
  }

  const botToken = String(process.env.TELEGRAM_BOT_TOKEN || "").trim();
  if (!botToken) return respond(res, 503, { code: "BOT_NOT_CONFIGURED" });

  const user = verifyTelegramInitData(req.headers["x-telegram-init-data"], botToken);
  if (!user) return respond(res, 401, { code: "INVALID_INIT_DATA" });
  if (!ALLOWED_ADMIN_IDS.has(user.id)) return respond(res, 403, { code: "NOT_ALLOWED" });

  const contentType = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (contentType !== DOCX_MIME) return respond(res, 415, { code: "INVALID_FILE_TYPE" });
  let reportBuffer;
  try {
    reportBuffer = await readReportBody(req);
  } catch (error) {
    if (error && error.code === "REPORT_TOO_LARGE") return respond(res, 413, { code: "REPORT_TOO_LARGE" });
    return respond(res, 400, { code: "INVALID_REPORT_BODY" });
  }
  if (!reportBuffer.length) return respond(res, 400, { code: "EMPTY_REPORT" });

  const requestedName = String(req.headers["x-report-filename"] || "");
  const fileName = /^[a-z0-9][a-z0-9._-]{0,119}\.docx$/i.test(requestedName)
    ? requestedName
    : "grant-academy-hisobot.docx";
  const form = new FormData();
  form.append("chat_id", user.id);
  form.append("document", new Blob([reportBuffer], { type: DOCX_MIME }), fileName);
  form.append("caption", "GRANT ACADEMY SARDORI — davr bo‘yicha hisobot");

  try {
    const telegramResponse = await fetch("https://api.telegram.org/bot" + botToken + "/sendDocument", {
      method: "POST",
      body: form
    });
    const telegramResult = await telegramResponse.json().catch(() => null);
    if (!telegramResponse.ok || !telegramResult || telegramResult.ok !== true) {
      const errorCode = Number(telegramResult && telegramResult.error_code);
      const description = String(telegramResult && telegramResult.description || "").toLowerCase();
      if (errorCode === 403 || (errorCode === 400 && /chat not found|bot was blocked|user is deactivated/.test(description))) {
        return respond(res, 409, { code: "BOT_CHAT_UNAVAILABLE" });
      }
      return respond(res, 502, { code: "TELEGRAM_SEND_FAILED" });
    }
    return respond(res, 200, { ok: true });
  } catch {
    return respond(res, 502, { code: "TELEGRAM_SEND_FAILED" });
  }
};

module.exports.config = { api: { bodyParser: false } };
