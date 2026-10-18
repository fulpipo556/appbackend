require('dotenv').config();
const crypto = require('crypto');
const dns = require('node:dns');
dns.setDefaultResultOrder('ipv4first');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const https = require('node:https');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const mysql = require('mysql2/promise');
const mammoth = require('mammoth');
const cheerio = require('cheerio');
const { v2: cloudinary } = require('cloudinary');

const app = express();
const port = process.env.PORT || 3000;
const adminEmails = new Set(
  (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean)
);
const appTimezoneOffset = process.env.APP_TIMEZONE_OFFSET || '-05:00';
if (!/^[+-](?:0\d|1\d|2[0-3]):[0-5]\d$/.test(appTimezoneOffset)) {
  throw new Error('APP_TIMEZONE_OFFSET debe tener formato ±HH:mm');
}

function roleForEmail(email, currentRole = 'teacher') {
  if (adminEmails.has(email.trim().toLowerCase())) return 'admin';
  return currentRole === 'attendant' ? 'attendant' : 'teacher';
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const uploadsDir = path.join(__dirname, 'uploads');
const cloudinaryFolder = process.env.CLOUDINARY_FOLDER || 'fotosyhojas';
fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

function cloudinaryConfigured() {
  return Boolean(
    process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
  );
}

function uploadToCloudinary(
  buffer,
  { folder, resourceType = 'auto', publicId, type = 'upload' } = {},
) {
  if (!cloudinaryConfigured()) {
    throw new Error('Cloudinary no está configurado en el backend');
  }
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: resourceType, type, public_id: publicId },
      (error, result) => error ? reject(error) : resolve(result)
    );
    stream.end(buffer);
  });
}

function cloudinaryRawUrl(publicId) {
  if (!publicId || !cloudinaryConfigured()) return '';
  return cloudinary.url(publicId, {
    secure: true,
    sign_url: true,
    resource_type: 'raw',
    type: 'authenticated',
  });
}

async function deleteCloudinaryAsset(
  publicId,
  resourceType = 'image',
  type = resourceType === 'raw' ? 'authenticated' : 'upload',
) {
  if (!publicId || !cloudinaryConfigured()) return;
  await cloudinary.uploader.destroy(publicId, {
    resource_type: resourceType,
    type,
    invalidate: true,
  });
}

const wordFileFilter = (_req, file, cb) => {
  const allowed = ['.docx'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowed.includes(ext)) {
    cb(null, true);
    return;
  }
  cb(new Error('Solo se permiten archivos DOCX reales (.docx)'));
};

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsDir),
    filename: (_req, file, cb) => {
      const safeName = file.originalname
        .replace(/[^a-zA-Z0-9_.-]/g, '_')
        .replace(/_+/g, '_');
      const timestamp = Date.now();
      cb(null, `${timestamp}_${safeName}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: wordFileFilter,
});
const previewUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: wordFileFilter,
});
const sectionMaxFileSizeMb = Number(process.env.SECTION_MAX_FILE_SIZE || 500);
const sectionUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: sectionMaxFileSizeMb * 1024 * 1024,
  },
  fileFilter: (_req, file, cb) => {
    const extension = path.extname(file.originalname).toLowerCase();
    const allowed = [
      '.jpg', '.jpeg', '.png', '.webp', '.gif',
      '.mp4', '.mov', '.webm', '.avi', '.mkv',
    ];
    if (allowed.includes(extension)) {
      cb(null, true);
      return;
    }
    cb(new Error('Solo se permiten imágenes y videos compatibles.'));
  },
});

function decodeZipEntryName(buffer) {
  try {
    return buffer.toString('utf8');
  } catch {
    return buffer.toString('latin1');
  }
}

function isValidDocxBuffer(fileBuffer) {
  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length < 4) {
    return false;
  }

  const pkSignature = fileBuffer.subarray(0, 4);
  const isZip = pkSignature.equals(Buffer.from([0x50, 0x4b, 0x03, 0x04])) ||
    pkSignature.equals(Buffer.from([0x50, 0x4b, 0x05, 0x06])) ||
    pkSignature.equals(Buffer.from([0x50, 0x4b, 0x07, 0x08]));

  if (!isZip) {
    return false;
  }

  const rawText = fileBuffer.toString('latin1');
  if (rawText.includes('[Content_Types].xml') && rawText.includes('word/document.xml')) {
    return true;
  }

  let offset = 0;
  let hasContentTypes = false;
  let hasDocumentXml = false;

  while (offset + 30 <= fileBuffer.length) {
    const signature = fileBuffer.readUInt32LE(offset);
    if (signature !== 0x04034b50) {
      break;
    }

    const fileNameLength = fileBuffer.readUInt16LE(offset + 26);
    const extraLength = fileBuffer.readUInt16LE(offset + 28);
    const fileNameOffset = offset + 30;
    const fileNameEnd = fileNameOffset + fileNameLength;

    if (fileNameEnd > fileBuffer.length) {
      return false;
    }

    const fileName = decodeZipEntryName(fileBuffer.subarray(fileNameOffset, fileNameEnd));
    if (fileName === '[Content_Types].xml') {
      hasContentTypes = true;
    }
    if (fileName === 'word/document.xml' || fileName.endsWith('/document.xml')) {
      hasDocumentXml = true;
    }

    const compressedSize = fileBuffer.readUInt32LE(offset + 18);
    const dataStart = fileNameEnd + extraLength;
    const dataEnd = dataStart + Math.max(compressedSize, 0);

    if (dataEnd > fileBuffer.length) {
      const nextLocalHeader = fileBuffer.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), offset + 4);
      if (nextLocalHeader > -1) {
        offset = nextLocalHeader;
      } else {
        break;
      }
    } else {
      offset = dataEnd;
    }

    if (hasContentTypes && hasDocumentXml) {
      return true;
    }
  }

  const centralDirectory = Buffer.from([0x50, 0x4b, 0x01, 0x02]);
  let centralOffset = fileBuffer.indexOf(centralDirectory);
  while (centralOffset !== -1 && centralOffset + 46 <= fileBuffer.length) {
    const nameLength = fileBuffer.readUInt16LE(centralOffset + 28);
    const fileNameStart = centralOffset + 46;
    const fileNameEnd = fileNameStart + nameLength;

    if (fileNameEnd <= fileBuffer.length) {
      const entryName = decodeZipEntryName(fileBuffer.subarray(fileNameStart, fileNameEnd));
      if (entryName === '[Content_Types].xml') {
        hasContentTypes = true;
      }
      if (entryName === 'word/document.xml' || entryName.endsWith('/document.xml')) {
        hasDocumentXml = true;
      }
    }

    if (hasContentTypes && hasDocumentXml) {
      return true;
    }

    centralOffset = fileBuffer.indexOf(centralDirectory, centralOffset + 1);
  }

  return false;
}

function getDocxValidationError(fileName, fileBuffer) {
  const extension = path.extname(String(fileName || '')).toLowerCase();
  if (extension !== '.docx') {
    return 'Solo se permiten archivos DOCX reales (.docx). Abre el documento en Word y guárdalo como Documento de Word.';
  }

  if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
    return 'El archivo DOCX está vacío o no se pudo leer correctamente.';
  }

  if (!isValidDocxBuffer(fileBuffer)) {
    return 'El archivo tiene extensión .docx, pero no es un DOCX válido. Abre el documento en Word y guárdalo de nuevo como Documento de Word (.docx).';
  }

  return null;
}

function extractDocumentBlocks(html) {
  const $ = cheerio.load(html);
  const blocks = [];

  function extractCellText(cell) {
    const parts = [];
    $(cell).children().each((_, child) => {
      const node = $(child);
      if (node.is('ol, ul')) {
        node.children('li').each((index, item) => {
          const text = $(item).text().trim();
          if (!text) return;
          const marker = node.is('ol') ? `${index + 1}. ` : '• ';
          parts.push(`${marker}${text}`);
        });
        return;
      }

      const text = node.text().trim();
      if (text) parts.push(text);
    });

    return parts.length > 0 ? parts.join('\n') : $(cell).text().trim();
  }

  $('body').children().each((_, element) => {
    const node = $(element);
    if (node.is('table')) {
      const rows = [];
      node.find('tr').each((_, row) => {
        const cells = [];
        $(row).children('th, td').each((_, cell) => {
          cells.push(extractCellText(cell));
        });
        if (cells.some(Boolean)) rows.push(cells);
      });
      if (rows.length > 0) blocks.push({ type: 'table', rows });
      return;
    }

    if (node.is('ul, ol')) {
      node.children('li').each((_, item) => {
        const text = $(item).text().trim();
        if (text) blocks.push({ type: 'paragraph', text });
      });
      return;
    }

    const text = node.text().trim();
    if (text) blocks.push({ type: 'paragraph', text });
  });

  return blocks;
}

const dbConfig = {
  host: process.env.DB_HOST ?? 'localhost',
  user: process.env.DB_USER ?? 'root',
  password: process.env.DB_PASSWORD ?? 'password',
  database: process.env.DB_NAME ?? 'flutter_login_db',
  port: Number(process.env.DB_PORT ?? 3306),
  waitForConnections: true,
  connectionLimit: 10,
};

const pool = mysql.createPool(dbConfig);
const smtpHost = process.env.SMTP_HOST || '';
const mailTransporter = process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD
  ? nodemailer.createTransport({
      host: smtpHost,
      port: Number(process.env.SMTP_PORT || 465),
      secure: process.env.SMTP_SECURE !== 'false',
      family: 4,
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD.replace(/\s+/g, ''),
      },
    })
  : null;
const gmailOAuthTransporter = process.env.GMAIL_CLIENT_ID &&
      process.env.GMAIL_CLIENT_SECRET &&
      process.env.GMAIL_REFRESH_TOKEN &&
      process.env.GMAIL_USER
    ? nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        family: 4,
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 15000,
        auth: {
          type: 'OAuth2',
          user: process.env.GMAIL_USER,
          clientId: process.env.GMAIL_CLIENT_ID,
          clientSecret: process.env.GMAIL_CLIENT_SECRET,
          refreshToken: process.env.GMAIL_REFRESH_TOKEN,
        },
      })
    : null;
const gmailApiConfigured = Boolean(
  process.env.GMAIL_CLIENT_ID &&
  process.env.GMAIL_CLIENT_SECRET &&
  process.env.GMAIL_REFRESH_TOKEN &&
  process.env.GMAIL_USER
);
const resendApiKey = process.env.RESEND_API_KEY || '';
const mailProvider = (process.env.MAIL_PROVIDER || '').trim().toLowerCase();
const apiPublicUrl = (process.env.API_PUBLIC_URL || `http://localhost:${port}`).replace(/\/$/, '');
const emailServiceConfigured = Boolean(gmailApiConfigured || mailTransporter || resendApiKey);

function sendEmailWithResend(message) {
  const from = process.env.RESEND_FROM || process.env.MAIL_FROM || '';
  if (!resendApiKey || !from) {
    return Promise.reject(new Error('El servicio Resend no está configurado'));
  }

  const payload = JSON.stringify({
    from,
    to: Array.isArray(message.to) ? message.to : [message.to],
    subject: message.subject,
    text: message.text,
    html: message.html,
  });

  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      timeout: 15000,
      headers: {
        Authorization: `Bearer ${resendApiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        responseBody += chunk;
      });
      response.on('end', () => {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          resolve();
          return;
        }
        reject(new Error(`Resend rechazó el correo (${response.statusCode}): ${responseBody}`));
      });
    });

    request.on('timeout', () => {
      request.destroy(new Error('Tiempo de espera agotado al conectar con Resend'));
    });
    request.on('error', reject);
    request.end(payload);
  });
}

function requestGoogleToken() {
  const payload = new URLSearchParams({
    client_id: process.env.GMAIL_CLIENT_ID,
    client_secret: process.env.GMAIL_CLIENT_SECRET,
    refresh_token: process.env.GMAIL_REFRESH_TOKEN,
    grant_type: 'refresh_token',
  }).toString();

  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      timeout: 15000,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        responseBody += chunk;
      });
      response.on('end', () => {
        let data;
        try {
          data = JSON.parse(responseBody);
        } catch {
          reject(new Error(`Google devolvió una respuesta inválida (${response.statusCode})`));
          return;
        }
        if (response.statusCode >= 200 && response.statusCode < 300 && data.access_token) {
          resolve(data.access_token);
          return;
        }
        reject(new Error(`Google rechazó la autenticación (${response.statusCode}): ${data.error || 'error desconocido'}`));
      });
    });
    request.on('timeout', () => request.destroy(new Error('Tiempo de espera agotado al autenticar con Google')));
    request.on('error', reject);
    request.end(payload);
  });
}

async function sendEmailWithGmailApi(message) {
  if (!gmailApiConfigured) {
    throw new Error(
      'MAIL_PROVIDER=gmail_api requiere GMAIL_USER, GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET y GMAIL_REFRESH_TOKEN',
    );
  }
  const headers = [
    `From: ${message.from || process.env.GMAIL_USER}`,
    `To: ${Array.isArray(message.to) ? message.to.join(', ') : message.to}`,
    `Subject: =?UTF-8?B?${Buffer.from(message.subject || '').toString('base64')}?=`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="mail-boundary"',
  ];
  const mimeMessage = [
    ...headers,
    '',
    '--mail-boundary',
    'Content-Type: text/plain; charset="UTF-8"',
    '',
    message.text || '',
    '--mail-boundary',
    'Content-Type: text/html; charset="UTF-8"',
    '',
    message.html || message.text || '',
    '--mail-boundary--',
  ].join('\r\n');
  const payload = JSON.stringify({
    raw: Buffer.from(mimeMessage).toString('base64url'),
  });
  const accessToken = await requestGoogleToken();

  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: 'gmail.googleapis.com',
      path: '/gmail/v1/users/me/messages/send',
      method: 'POST',
      timeout: 15000,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (response) => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        responseBody += chunk;
      });
      response.on('end', () => {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          resolve();
          return;
        }
        reject(new Error(`Gmail API rechazó el correo (${response.statusCode}): ${responseBody}`));
      });
    });
    request.on('timeout', () => request.destroy(new Error('Tiempo de espera agotado al enviar con Gmail API')));
    request.on('error', reject);
    request.end(payload);
  });
}

async function sendEmail(message) {
  const normalizedMessage = {
    ...message,
    from: message.from || process.env.MAIL_FROM || process.env.GMAIL_USER || process.env.SMTP_USER,
  };
  if (gmailApiConfigured) {
    await sendEmailWithGmailApi(normalizedMessage);
    return;
  }
  if (mailProvider === 'resend' || resendApiKey) {
    if (!resendApiKey) {
      throw new Error('MAIL_PROVIDER=resend requiere configurar RESEND_API_KEY');
    }
    await sendEmailWithResend(normalizedMessage);
    return;
  }
  if (mailProvider === 'gmail' || mailProvider === 'gmail_oauth2') {
    if (!gmailOAuthTransporter) {
      throw new Error(
        'MAIL_PROVIDER=gmail requiere GMAIL_USER, GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET y GMAIL_REFRESH_TOKEN',
      );
    }
    await gmailOAuthTransporter.sendMail(normalizedMessage);
    return;
  }
  if (mailProvider === 'gmail_api') {
    await sendEmailWithGmailApi(normalizedMessage);
    return;
  }
  if (!emailServiceConfigured) {
    throw new Error('El servicio de correo no está configurado');
  }
  await mailTransporter.sendMail(normalizedMessage);
}

function hashValue(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeHashEquals(left, right) {
  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

async function sendVerificationEmail({ name, email, code, token }) {
  const verificationUrl = new URL('/api/verify-email', apiPublicUrl);
  verificationUrl.searchParams.set('token', token);

  await sendEmail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Confirma tu cuenta',
    text: `Hola ${name}, tu código de verificación es ${code}. También puedes activar tu cuenta con este enlace: ${verificationUrl}`,
    html: `<p>Hola ${escapeHtml(name)},</p><p>Tu código de verificación es:</p><p style="font-size:24px;font-weight:bold;letter-spacing:4px">${code}</p><p>O termina de crear tu cuenta con este enlace:</p><p><a href="${verificationUrl}">Verificar correo y activar cuenta</a></p><p>El código y el enlace vencen en 15 minutos.</p>`,
  });
}

async function sendPasswordSetupEmail({ name, email, token }) {
  const setupUrl = new URL('/api/password-setup', apiPublicUrl);
  setupUrl.searchParams.set('token', token);

  await sendEmail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Configura la contraseña de tu cuenta',
    text: `Hola ${name}, se creó una cuenta para ti. Configura tu contraseña personal en este enlace: ${setupUrl}. El enlace vence en 24 horas.`,
    html: `<p>Hola ${escapeHtml(name)},</p><p>Se creó una cuenta para ti. Usa el siguiente enlace para configurar tu contraseña personal:</p><p><a href="${setupUrl}">Configurar contraseña</a></p><p>El enlace vence en 24 horas y solo puede utilizarse una vez.</p>`,
  });
}

async function sendPasswordResetEmail({ name, email, token }) {
  const resetUrl = new URL('/api/password-setup', apiPublicUrl);
  resetUrl.searchParams.set('token', token);

  await sendEmail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: 'Restablece tu contraseña',
    text: `Hola ${name}, recibimos una solicitud para cambiar tu contraseña. Usa este enlace: ${resetUrl}. Vence en 1 hora. Si no fuiste tú, ignora este correo.`,
    html: `<p>Hola ${escapeHtml(name)},</p><p>Recibimos una solicitud para cambiar tu contraseña. Usa el siguiente enlace:</p><p><a href="${resetUrl}">Cambiar contraseña</a></p><p>El enlace vence en 1 hora y solo puede utilizarse una vez. Si no fuiste tú, ignora este correo.</p>`,
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

async function createAdminUser({ name, email, role = 'teacher', password = '' }) {
  const normalizedName = name.trim();
  const normalizedEmail = email.trim().toLowerCase();
  const passwordHash = await bcrypt.hash(password || crypto.randomBytes(32).toString('hex'), 10);
  let userId;

  try {
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password, role, password_setup_required) VALUES (?, ?, ?, ?, 1)',
      [normalizedName, normalizedEmail, passwordHash, roleForEmail(normalizedEmail, role)]
    );
    userId = result.insertId;
    await sendPasswordSetupInvitation(userId);
  } catch (error) {
    if (userId) {
      await pool.query('DELETE FROM users WHERE id = ?', [userId]);
    }
    throw error;
  }

  return { name: normalizedName, email: normalizedEmail };
}

async function importTeacher({ name, email }) {
  const normalizedName = name.trim();
  const normalizedEmail = email.trim().toLowerCase();
  const updateExistingTeacher = async (user) => {
    if (user.role !== 'teacher') {
      return {
        name: user.name,
        email: normalizedEmail,
        status: 'already_registered',
        message: 'Este correo ya está registrado como administrador',
      };
    }
    if (user.name === normalizedName) {
      return {
        name: user.name,
        email: normalizedEmail,
        status: 'already_registered',
        message: 'El docente ya está registrado sin cambios',
      };
    }
    await pool.query(
      'UPDATE users SET name = ? WHERE id = ?',
      [normalizedName, user.id]
    );
    return {
      name: normalizedName,
      email: normalizedEmail,
      status: 'updated',
      message: 'Se actualizó el nombre del docente',
    };
  };

  const [existingUsers] = await pool.query(
    'SELECT id, name, role FROM users WHERE email = ?',
    [normalizedEmail]
  );
  if (existingUsers.length > 0) {
    return updateExistingTeacher(existingUsers[0]);
  }

  const passwordHash = await bcrypt.hash(
    crypto.randomBytes(32).toString('hex'),
    10
  );
  try {
    await pool.query(
      'INSERT INTO users (name, email, password, role, password_setup_required) VALUES (?, ?, ?, ?, 1)',
      [normalizedName, normalizedEmail, passwordHash, 'teacher']
    );
    return {
      name: normalizedName,
      email: normalizedEmail,
      status: 'created',
      message: 'Docente registrado',
    };
  } catch (error) {
    if (error.code !== 'ER_DUP_ENTRY') throw error;
    const [racedUsers] = await pool.query(
      'SELECT id, name, role FROM users WHERE email = ?',
      [normalizedEmail]
    );
    if (racedUsers.length === 0) throw error;
    return updateExistingTeacher(racedUsers[0]);
  }
}

async function sendPasswordSetupInvitation(userId) {
  if (!emailServiceConfigured) {
    throw new Error('El servicio de correo no está configurado');
  }

  const [users] = await pool.query(
    'SELECT id, name, email, password_setup_required FROM users WHERE id = ?',
    [userId]
  );
  if (users.length === 0) {
    const error = new Error('Usuario no encontrado');
    error.code = 'USER_NOT_FOUND';
    throw error;
  }
  const user = users[0];
  if (!user.password_setup_required) {
    const error = new Error('El docente ya configuró su contraseña');
    error.code = 'PASSWORD_ALREADY_CONFIGURED';
    throw error;
  }

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashValue(token);
  const [result] = await pool.query(
    'INSERT INTO password_setup_tokens (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))',
    [user.id, tokenHash]
  );
  try {
    await sendPasswordSetupEmail({
      name: user.name,
      email: user.email,
      token,
    });
  } catch (error) {
    await pool.query('DELETE FROM password_setup_tokens WHERE id = ?', [
      result.insertId,
    ]);
    throw error;
  }

  await pool.query(
    'UPDATE password_setup_tokens SET used_at = NOW() WHERE user_id = ? AND id <> ? AND used_at IS NULL',
    [user.id, result.insertId]
  );
  return { name: user.name, email: user.email };
}

function passwordSetupPage(token, message = '') {
  const messageHtml = message ? `<p>${escapeHtml(message)}</p>` : '';
  return `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Configurar contraseña</title><body style="font:16px sans-serif;max-width:560px;margin:15vh auto;padding:24px"><h1>Configura tu contraseña</h1>${messageHtml}<form method="post" action="/api/password-setup"><input type="hidden" name="token" value="${escapeHtml(token)}"><label for="password">Nueva contraseña</label><br><input id="password" name="password" type="password" minlength="8" maxlength="128" required autocomplete="new-password"><p>Debe tener al menos 8 caracteres.</p><button style="padding:12px 20px" type="submit">Guardar contraseña</button></form></body></html>`;
}

function passwordSetupResultPage(title, message) {
  return `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title><body style="font:16px sans-serif;max-width:560px;margin:15vh auto;padding:24px"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></body></html>`;
}

async function activatePendingUser(pendingUserId) {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [pendingRows] = await connection.query(
      'SELECT id, name, email, password_hash FROM pending_users WHERE id = ? FOR UPDATE',
      [pendingUserId]
    );

    if (pendingRows.length === 0) {
      await connection.rollback();
      return false;
    }

    const pendingUser = pendingRows[0];
    await connection.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [
        pendingUser.name,
        pendingUser.email,
        pendingUser.password_hash,
        roleForEmail(pendingUser.email),
      ]
    );
    await connection.query('DELETE FROM pending_users WHERE id = ?', [pendingUserId]);
    await connection.commit();
    return true;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

function verificationResultPage(title, message) {
  return `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title><body style="font:16px sans-serif;max-width:560px;margin:15vh auto;padding:24px"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><p>Ya puedes volver a la aplicación e iniciar sesión.</p></body></html>`;
}

function verificationConfirmationPage(token) {
  return `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Confirma tu cuenta</title><body style="font:16px sans-serif;max-width:560px;margin:15vh auto;padding:24px"><h1>Termina de crear tu cuenta</h1><p>Confirma tu correo para activar la cuenta.</p><form method="post" action="/api/verify-email/link"><input type="hidden" name="token" value="${token}"><button style="padding:12px 20px" type="submit">Confirmar correo y activar cuenta</button></form></body></html>`;
}

async function initDatabase() {
  const connection = await mysql.createConnection({
    host: dbConfig.host,
    user: dbConfig.user,
    password: dbConfig.password,
    port: dbConfig.port,
  });

  await connection.query(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\`;`);
  await connection.end();

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(150) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      role ENUM('teacher', 'admin', 'attendant') NOT NULL DEFAULT 'teacher',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  const [userRoleColumn] = await pool.query("SHOW COLUMNS FROM users LIKE 'role'");
  if (userRoleColumn.length === 0) {
    await pool.query(
      "ALTER TABLE users ADD COLUMN role ENUM('teacher', 'admin', 'attendant') NOT NULL DEFAULT 'teacher'"
    );
  } else if (!String(userRoleColumn[0].Type).includes('attendant')) {
    await pool.query(
      "ALTER TABLE users MODIFY COLUMN role ENUM('teacher', 'admin', 'attendant') NOT NULL DEFAULT 'teacher'"
    );
  }
  const [userGroupColumn] = await pool.query("SHOW COLUMNS FROM users LIKE 'group_id'");
  if (userGroupColumn.length === 0) {
    await pool.query('ALTER TABLE users ADD COLUMN group_id INT NULL');
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance_records (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      kind ENUM('attendance', 'break') NOT NULL,
      event_date DATE NOT NULL,
      recorded_by INT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_attendance_user_kind_day (user_id, kind, event_date),
      CONSTRAINT fk_attendance_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance_schedules (
      event_date DATE PRIMARY KEY,
      attendance_start TIME NOT NULL,
      attendance_end TIME NOT NULL,
      break_start TIME NOT NULL,
      break_end TIME NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance_schedule_windows (
      id INT AUTO_INCREMENT PRIMARY KEY,
      event_date DATE NOT NULL,
      attendance_start TIME NOT NULL,
      attendance_end TIME NOT NULL,
      break_start TIME NOT NULL,
      break_end TIME NOT NULL,
      attendance_enabled TINYINT(1) NOT NULL DEFAULT 1,
      break_enabled TINYINT(1) NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_attendance_schedule_date (event_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
  const [attendanceEnabledColumn] = await pool.query(
    "SHOW COLUMNS FROM attendance_schedule_windows LIKE 'attendance_enabled'"
  );
  if (attendanceEnabledColumn.length === 0) {
    await pool.query(
      'ALTER TABLE attendance_schedule_windows ADD COLUMN attendance_enabled TINYINT(1) NOT NULL DEFAULT 1'
    );
  }
  const [breakEnabledColumn] = await pool.query(
    "SHOW COLUMNS FROM attendance_schedule_windows LIKE 'break_enabled'"
  );
  if (breakEnabledColumn.length === 0) {
    await pool.query(
      'ALTER TABLE attendance_schedule_windows ADD COLUMN break_enabled TINYINT(1) NOT NULL DEFAULT 1'
    );
  }
  await pool.query(`
    INSERT IGNORE INTO attendance_schedule_windows
      (event_date, attendance_start, attendance_end, break_start, break_end)
    SELECT event_date, attendance_start, attendance_end, break_start, break_end
    FROM attendance_schedules
  `);

  const [passwordSetupColumn] = await pool.query(
    "SHOW COLUMNS FROM users LIKE 'password_setup_required'"
  );
  if (passwordSetupColumn.length === 0) {
    await pool.query(
      'ALTER TABLE users ADD COLUMN password_setup_required TINYINT(1) NOT NULL DEFAULT 0'
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS workshops (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(150) NOT NULL UNIQUE,
      capacity INT UNSIGNED NOT NULL DEFAULT 0,
      address VARCHAR(255) NOT NULL DEFAULT '',
      room VARCHAR(150) NOT NULL DEFAULT '',
      start_time VARCHAR(5) NOT NULL DEFAULT '',
      end_time VARCHAR(5) NOT NULL DEFAULT '',
      day_times TEXT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  for (const [column, definition] of [
    ['address', "VARCHAR(255) NOT NULL DEFAULT ''"],
    ['room', "VARCHAR(150) NOT NULL DEFAULT ''"],
    ['start_time', "VARCHAR(5) NOT NULL DEFAULT ''"],
    ['end_time', "VARCHAR(5) NOT NULL DEFAULT ''"],
    ['day_times', 'TEXT NULL'],
  ]) {
    const [found] = await pool.query(`SHOW COLUMNS FROM workshops LIKE '${column}'`);
    if (found.length === 0) {
      await pool.query(`ALTER TABLE workshops ADD COLUMN ${column} ${definition}`);
    }
  }

  const [workshopCapacityColumn] = await pool.query(
    "SHOW COLUMNS FROM workshops LIKE 'capacity'"
  );
  if (workshopCapacityColumn.length === 0) {
    await pool.query(
      'ALTER TABLE workshops ADD COLUMN capacity INT UNSIGNED NOT NULL DEFAULT 0'
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS workshop_teachers (
      workshop_id INT NOT NULL,
      user_id INT NOT NULL,
      PRIMARY KEY (workshop_id, user_id),
      CONSTRAINT fk_workshop_teacher_workshop FOREIGN KEY (workshop_id)
        REFERENCES workshops(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
      CONSTRAINT fk_workshop_teacher_user FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS workshop_groups (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL UNIQUE,
      member_count INT UNSIGNED NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  const [groupMemberCountColumn] = await pool.query(
    "SHOW COLUMNS FROM workshop_groups LIKE 'member_count'"
  );
  if (groupMemberCountColumn.length === 0) {
    await pool.query(
      'ALTER TABLE workshop_groups ADD COLUMN member_count INT UNSIGNED NOT NULL DEFAULT 0'
    );
  }
  await pool.query(
    `INSERT INTO workshop_groups (name)
     VALUES ('Grupo A'), ('Grupo B'), ('Grupo C'), ('Grupo D')
     ON DUPLICATE KEY UPDATE name = VALUES(name)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS workshop_rotation_assignments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      rotation_date DATE NOT NULL,
      group_id INT NOT NULL,
      workshop_id INT NOT NULL,
      UNIQUE KEY uq_workshop_rotation_group_date (rotation_date, group_id),
      CONSTRAINT fk_rotation_group FOREIGN KEY (group_id)
        REFERENCES workshop_groups(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
      CONSTRAINT fk_rotation_workshop FOREIGN KEY (workshop_id)
        REFERENCES workshops(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pending_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(150) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      code_hash CHAR(64) NOT NULL,
      token_hash CHAR(64) NOT NULL,
      expires_at DATETIME NOT NULL,
      attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
      last_sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_setup_tokens (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      token_hash CHAR(64) NOT NULL UNIQUE,
      expires_at DATETIME NOT NULL,
      used_at DATETIME NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_password_setup_user FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    UPDATE users
    SET password_setup_required = 1
    WHERE EXISTS (
      SELECT 1 FROM password_setup_tokens
      WHERE password_setup_tokens.user_id = users.id
        AND password_setup_tokens.used_at IS NULL
    )
  `);

  const [pendingColumns] = await pool.query("SHOW COLUMNS FROM pending_users LIKE 'last_sent_at'");
  if (pendingColumns.length === 0) {
    await pool.query(
      'ALTER TABLE pending_users ADD COLUMN last_sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP'
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_types (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(80) NOT NULL UNIQUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS speakers (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      role VARCHAR(150) NULL,
      institution VARCHAR(150) NULL,
      bio TEXT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  for (const [column, definition] of [
    ['photo_path', 'VARCHAR(255) NULL'],
    ['photo_cloudinary_id', 'VARCHAR(255) NULL'],
    ['cv_file_name', 'VARCHAR(255) NULL'],
    ['cv_file_path', 'VARCHAR(255) NULL'],
    ['cv_cloudinary_id', 'VARCHAR(255) NULL'],
    ['cv_word_count', 'INT UNSIGNED NOT NULL DEFAULT 0'],
  ]) {
    const [found] = await pool.query(`SHOW COLUMNS FROM speakers LIKE '${column}'`);
    if (found.length === 0) {
      await pool.query(`ALTER TABLE speakers ADD COLUMN ${column} ${definition}`);
    }
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activities (
      id INT AUTO_INCREMENT PRIMARY KEY,
      activity TEXT NOT NULL,
      title VARCHAR(200) NOT NULL,
      description TEXT NULL,
      date DATE NOT NULL,
      time TIME NOT NULL DEFAULT '00:00:00',
      time_end TIME NULL,
      responsible TEXT NULL,
      place TEXT NULL,
      modality VARCHAR(100) NOT NULL,
      activity_type_id INT NULL,
      file_name VARCHAR(255) NULL,
      file_path VARCHAR(255) NULL,
      file_cloudinary_id VARCHAR(255) NULL,
      file_data MEDIUMBLOB NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_activity_type FOREIGN KEY (activity_type_id)
        REFERENCES activity_types(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS content_sections (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      body TEXT NOT NULL,
      image_path VARCHAR(255) NULL,
      video_path VARCHAR(255) NULL,
      video_url TEXT NULL,
      display_order INT NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
  const [activityCloudColumn] = await pool.query(
    "SHOW COLUMNS FROM activities LIKE 'file_cloudinary_id'"
  );
  if (activityCloudColumn.length === 0) {
    await pool.query(
      'ALTER TABLE activities ADD COLUMN file_cloudinary_id VARCHAR(255) NULL'
    );
  }
  for (const [column, definition] of [
    ['image_cloudinary_id', 'VARCHAR(255) NULL'],
    ['video_cloudinary_id', 'VARCHAR(255) NULL'],
  ]) {
    const [found] = await pool.query(`SHOW COLUMNS FROM content_sections LIKE '${column}'`);
    if (found.length === 0) {
      await pool.query(`ALTER TABLE content_sections ADD COLUMN ${column} ${definition}`);
    }
  }
  const [sectionOrderColumn] = await pool.query(
    "SHOW COLUMNS FROM content_sections LIKE 'display_order'"
  );
  if (sectionOrderColumn.length === 0) {
    await pool.query(
      'ALTER TABLE content_sections ADD COLUMN display_order INT NOT NULL DEFAULT 0'
    );
    const [sections] = await pool.query(
      'SELECT id FROM content_sections ORDER BY id DESC'
    );
    for (const [index, section] of sections.entries()) {
      await pool.query(
        'UPDATE content_sections SET display_order = ? WHERE id = ?',
        [index, section.id]
      );
    }
  }

  const [activityColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'activity'");
  if (activityColumn.length > 0 && !activityColumn[0].Type.toLowerCase().startsWith('text')) {
    await pool.query('ALTER TABLE activities MODIFY COLUMN activity TEXT NOT NULL');
  }

  const [fileNameColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'file_name'");
  if (fileNameColumn.length > 0 && fileNameColumn[0].Null === 'NO') {
    await pool.query('ALTER TABLE activities MODIFY COLUMN file_name VARCHAR(255) NULL');
  }

  const [filePathColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'file_path'");
  if (filePathColumn.length > 0 && filePathColumn[0].Null === 'NO') {
    await pool.query('ALTER TABLE activities MODIFY COLUMN file_path VARCHAR(255) NULL');
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_speakers (
      activity_id INT NOT NULL,
      speaker_id INT NOT NULL,
      PRIMARY KEY (activity_id, speaker_id),
      CONSTRAINT fk_activity_speaker_activity FOREIGN KEY (activity_id)
        REFERENCES activities(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
      CONSTRAINT fk_activity_speaker_speaker FOREIGN KEY (speaker_id)
        REFERENCES speakers(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  const [activityTimeColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'time'");
  if (activityTimeColumn.length === 0) {
    await pool.query(
      "ALTER TABLE activities ADD COLUMN time TIME NOT NULL DEFAULT '00:00:00' AFTER date"
    );
  }

  const [activityTimeEndColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'time_end'");
  if (activityTimeEndColumn.length === 0) {
    await pool.query('ALTER TABLE activities ADD COLUMN time_end TIME NULL AFTER time');
  }

  const [responsibleColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'responsible'");
  if (responsibleColumn.length === 0) {
    await pool.query('ALTER TABLE activities ADD COLUMN responsible TEXT NULL AFTER time_end');
  }

  const [placeColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'place'");
  if (placeColumn.length === 0) {
    await pool.query('ALTER TABLE activities ADD COLUMN place TEXT NULL AFTER responsible');
  }

  const [fileDataColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'file_data'");
  if (fileDataColumn.length === 0) {
    await pool.query(
      'ALTER TABLE activities ADD COLUMN file_data MEDIUMBLOB NULL AFTER file_path'
    );
  }

  const [titleColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'title'");
  if (titleColumn.length === 0) {
    await pool.query(
      "ALTER TABLE activities ADD COLUMN title VARCHAR(200) NOT NULL DEFAULT '' AFTER activity"
    );
  }

  const [descriptionColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'description'");
  if (descriptionColumn.length === 0) {
    await pool.query(
      'ALTER TABLE activities ADD COLUMN description TEXT NULL AFTER title'
    );
  }

  const [typeColumn] = await pool.query("SHOW COLUMNS FROM activities LIKE 'activity_type_id'");
  if (typeColumn.length === 0) {
    await pool.query(
      'ALTER TABLE activities ADD COLUMN activity_type_id INT NULL AFTER modality'
    );
  }

  await pool.query(`
    INSERT INTO activity_types (name)
    VALUES ('Taller'), ('Conferencia'), ('Seminario'), ('Curso'), ('Otro')
    ON DUPLICATE KEY UPDATE name = VALUES(name)
  `);

  console.log('Base de datos inicializada');
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido o expirado' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ message: 'No tienes permisos para acceder a este recurso' });
    }
    next();
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, message: 'API funcionando correctamente' });
});

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Nombre, email y contraseña son obligatorios' });
  }

  if (!emailServiceConfigured) {
    return res.status(503).json({ message: 'El servicio de correo no está configurado' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  try {
    await pool.query('DELETE FROM pending_users WHERE expires_at <= NOW()');
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE email = ?', [normalizedEmail]);

    if (existingUsers.length > 0) {
      return res.status(409).json({ message: 'El usuario ya existe' });
    }

    const [pendingUsers] = await pool.query('SELECT id FROM pending_users WHERE email = ?', [normalizedEmail]);
    if (pendingUsers.length > 0) {
      return res.status(409).json({ message: 'Ya hay una verificación pendiente para este correo' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    const [result] = await pool.query(
      `INSERT INTO pending_users
        (name, email, password_hash, code_hash, token_hash, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [name.trim(), normalizedEmail, passwordHash, hashValue(code), hashValue(token), expiresAt]
    );

    try {
      await sendVerificationEmail({ name: name.trim(), email: normalizedEmail, code, token });
    } catch (error) {
      await pool.query('DELETE FROM pending_users WHERE id = ?', [result.insertId]);
      console.error('Error al enviar correo de verificación:', error.message);
      return res.status(502).json({ message: 'No se pudo enviar el correo de verificación' });
    }

    return res.status(202).json({
      message: 'Te enviamos un código y un enlace para activar tu cuenta',
      email: normalizedEmail,
    });
  } catch (error) {
    console.error('Error en register:', error);
    return res.status(500).json({ message: 'Error al registrar usuario' });
  }
});

app.post('/api/resend-verification', async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';

  if (!email) {
    return res.status(400).json({ message: 'Correo obligatorio' });
  }
  if (!emailServiceConfigured) {
    return res.status(503).json({ message: 'El servicio de correo no está configurado' });
  }

  const connection = await pool.getConnection();
  let inTransaction = false;
  try {
    await connection.beginTransaction();
    inTransaction = true;
    const [pendingRows] = await connection.query(
      'SELECT * FROM pending_users WHERE email = ? FOR UPDATE',
      [email]
    );

    if (pendingRows.length === 0) {
      const [users] = await connection.query('SELECT id FROM users WHERE email = ?', [email]);
      await connection.rollback();
      inTransaction = false;
      return res.status(users.length > 0 ? 409 : 404).json({
        message: users.length > 0
          ? 'Esta cuenta ya está verificada'
          : 'No hay una cuenta pendiente para este correo',
      });
    }

    const pendingUser = pendingRows[0];
    if (Date.now() - new Date(pendingUser.last_sent_at).getTime() < 60 * 1000) {
      await connection.rollback();
      inTransaction = false;
      return res.status(429).json({ message: 'Espera un minuto antes de pedir otro código' });
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    await connection.query(
      `UPDATE pending_users
       SET code_hash = ?, token_hash = ?, expires_at = ?, attempts = 0, last_sent_at = NOW()
       WHERE id = ?`,
      [hashValue(code), hashValue(token), expiresAt, pendingUser.id]
    );

    try {
      await sendVerificationEmail({
        name: pendingUser.name,
        email: pendingUser.email,
        code,
        token,
      });
    } catch (error) {
      await connection.rollback();
      inTransaction = false;
      console.error('Error al reenviar correo de verificación:', error.message);
      return res.status(502).json({ message: 'No se pudo reenviar el correo de verificación' });
    }

    await connection.commit();
    inTransaction = false;
    return res.status(202).json({ message: 'Enviamos un nuevo código y enlace de verificación' });
  } catch (error) {
    if (inTransaction) await connection.rollback();
    console.error('Error al reenviar verificación:', error);
    return res.status(500).json({ message: 'No se pudo reenviar el código' });
  } finally {
    connection.release();
  }
});

app.post('/api/verify-email', async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';

  if (!email || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ message: 'Correo o código inválido' });
  }

  try {
    const [pendingRows] = await pool.query('SELECT * FROM pending_users WHERE email = ?', [email]);
    if (pendingRows.length === 0) {
      return res.status(404).json({ message: 'No hay una cuenta pendiente para este correo' });
    }

    const pendingUser = pendingRows[0];
    if (new Date(pendingUser.expires_at).getTime() <= Date.now()) {
      await pool.query('DELETE FROM pending_users WHERE id = ?', [pendingUser.id]);
      return res.status(410).json({ message: 'El código venció; inicia el registro de nuevo' });
    }

    if (!safeHashEquals(pendingUser.code_hash, hashValue(code))) {
      if (pendingUser.attempts >= 4) {
        await pool.query('DELETE FROM pending_users WHERE id = ?', [pendingUser.id]);
        return res.status(429).json({ message: 'Se agotaron los intentos; inicia el registro de nuevo' });
      }
      await pool.query('UPDATE pending_users SET attempts = attempts + 1 WHERE id = ?', [pendingUser.id]);
      return res.status(400).json({ message: 'El código no es correcto' });
    }

    await activatePendingUser(pendingUser.id);
    return res.json({ message: 'Correo verificado. Ya puedes iniciar sesión' });
  } catch (error) {
    console.error('Error al verificar correo:', error);
    return res.status(500).json({ message: 'No se pudo verificar el correo' });
  }
});

app.get('/api/verify-email', async (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : '';
  if (!/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).send(verificationResultPage('Enlace inválido', 'El enlace de verificación no es válido.'));
  }

  try {
    const [pendingRows] = await pool.query('SELECT id, expires_at FROM pending_users WHERE token_hash = ?', [hashValue(token)]);
    if (pendingRows.length === 0) {
      return res.status(404).send(verificationResultPage('Enlace no disponible', 'La cuenta ya fue activada o el enlace no es válido.'));
    }

    const pendingUser = pendingRows[0];
    if (new Date(pendingUser.expires_at).getTime() <= Date.now()) {
      await pool.query('DELETE FROM pending_users WHERE id = ?', [pendingUser.id]);
      return res.status(410).send(verificationResultPage('Enlace vencido', 'Inicia el registro de nuevo para recibir otro enlace.'));
    }

    return res.send(verificationConfirmationPage(token));
  } catch (error) {
    console.error('Error al activar cuenta desde enlace:', error);
    return res.status(500).send(verificationResultPage('Error', 'No se pudo activar la cuenta.'));
  }
});

app.post('/api/verify-email/link', async (req, res) => {
  const token = typeof req.body.token === 'string' ? req.body.token : '';
  if (!/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).send(verificationResultPage('Enlace inválido', 'El enlace de verificación no es válido.'));
  }

  try {
    const [pendingRows] = await pool.query('SELECT id, expires_at FROM pending_users WHERE token_hash = ?', [hashValue(token)]);
    if (pendingRows.length === 0) {
      return res.status(404).send(verificationResultPage('Enlace no disponible', 'La cuenta ya fue activada o el enlace no es válido.'));
    }

    const pendingUser = pendingRows[0];
    if (new Date(pendingUser.expires_at).getTime() <= Date.now()) {
      await pool.query('DELETE FROM pending_users WHERE id = ?', [pendingUser.id]);
      return res.status(410).send(verificationResultPage('Enlace vencido', 'Inicia el registro de nuevo para recibir otro enlace.'));
    }

    await activatePendingUser(pendingUser.id);
    return res.send(verificationResultPage('Cuenta activada', 'Tu correo fue verificado correctamente.'));
  } catch (error) {
    console.error('Error al activar cuenta desde enlace:', error);
    return res.status(500).send(verificationResultPage('Error', 'No se pudo activar la cuenta.'));
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email y contraseña son obligatorios' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const user = rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const role = roleForEmail(user.email, user.role);
    if (user.role !== role) {
      await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, user.id]);
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '12h' }
    );

    return res.json({
      message: 'Login exitoso',
      token,
      user: { id: user.id, name: user.name, email: user.email, role },
    });
  } catch (error) {
    console.error('Error en login:', error);
    return res.status(500).json({ message: 'Error al iniciar sesión' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ message: 'Ingresa un correo válido' });
  }

  const genericResponse = {
    message: 'Si el correo está registrado, enviamos un enlace para cambiar tu contraseña.',
  };

  try {
    const [users] = await pool.query(
      'SELECT id, name, email FROM users WHERE email = ?',
      [email]
    );
    if (users.length === 0) {
      return res.json(genericResponse);
    }
    if (!emailServiceConfigured) {
      return res.status(503).json({ message: 'El servicio de correo no está configurado' });
    }

    const user = users[0];
    const token = crypto.randomBytes(32).toString('hex');
    const [result] = await pool.query(
      'INSERT INTO password_setup_tokens (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))',
      [user.id, hashValue(token)]
    );
    try {
      await sendPasswordResetEmail({ name: user.name, email: user.email, token });
    } catch (error) {
      await pool.query('DELETE FROM password_setup_tokens WHERE id = ?', [result.insertId]);
      throw error;
    }
    await pool.query(
      'UPDATE password_setup_tokens SET used_at = NOW() WHERE user_id = ? AND id <> ? AND used_at IS NULL',
      [user.id, result.insertId]
    );
    return res.json(genericResponse);
  } catch (error) {
    console.error('Error en recuperación de contraseña:', error);
    return res.status(500).json({ message: 'No se pudo enviar el correo. Inténtalo más tarde.' });
  }
});

app.get('/api/password-setup', async (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : '';
  if (!/^[a-f0-9]{64}$/i.test(token)) {
    return res.status(400).send(passwordSetupResultPage(
      'Enlace inválido',
      'El enlace para configurar la contraseña no es válido.'
    ));
  }

  try {
    const [tokens] = await pool.query(
      'SELECT id FROM password_setup_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()',
      [hashValue(token)]
    );
    if (tokens.length === 0) {
      return res.status(400).send(passwordSetupResultPage(
        'Enlace vencido',
        'Solicita al administrador que vuelva a enviar la invitación.'
      ));
    }
    return res.send(passwordSetupPage(token));
  } catch (error) {
    console.error('Error al validar enlace de contraseña:', error);
    return res.status(500).send(passwordSetupResultPage(
      'Error',
      'No se pudo validar el enlace. Inténtalo más tarde.'
    ));
  }
});

app.post('/api/password-setup', async (req, res) => {
  const token = typeof req.body.token === 'string' ? req.body.token : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!/^[a-f0-9]{64}$/i.test(token) || password.length < 8 || password.length > 128) {
    return res.status(400).send(passwordSetupPage(
      token,
      'El enlace no es válido o la contraseña no cumple los requisitos.'
    ));
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [tokens] = await connection.query(
      'SELECT id, user_id FROM password_setup_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW() FOR UPDATE',
      [hashValue(token)]
    );
    if (tokens.length === 0) {
      await connection.rollback();
      return res.status(400).send(passwordSetupResultPage(
        'Enlace vencido',
        'Solicita al administrador que vuelva a enviar la invitación.'
      ));
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await connection.query('UPDATE users SET password = ? WHERE id = ?', [
      passwordHash,
      tokens[0].user_id,
    ]);
    await connection.query(
      'UPDATE users SET password_setup_required = 0 WHERE id = ?',
      [tokens[0].user_id]
    );
    await connection.query(
      'UPDATE password_setup_tokens SET used_at = NOW() WHERE id = ?',
      [tokens[0].id]
    );
    await connection.commit();
    return res.send(passwordSetupResultPage(
      'Contraseña configurada',
      'Tu contraseña se guardó correctamente. Ya puedes iniciar sesión en la aplicación.'
    ));
  } catch (error) {
    await connection.rollback();
    console.error('Error al configurar contraseña:', error);
    return res.status(500).send(passwordSetupResultPage(
      'Error',
      'No se pudo guardar la contraseña. Inténtalo más tarde.'
    ));
  } finally {
    connection.release();
  }
});

app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, role FROM users WHERE id = ?', [req.user.id]);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    return res.json({ user: rows[0] });
  } catch (error) {
    console.error('Error en profile:', error);
    return res.status(500).json({ message: 'Error al consultar perfil' });
  }
});

app.get('/api/my/workshops', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT w.id, w.title, w.capacity, w.address, w.room,
              w.start_time, w.end_time, w.day_times
       FROM workshops w
       ORDER BY w.title, w.id`,
    );
    const [assignments] = await pool.query(
      `SELECT wt.workshop_id, w.title
       FROM workshop_teachers wt
       JOIN workshops w ON w.id = wt.workshop_id
       WHERE wt.user_id = ?`,
      [req.user.id]
    );
    const normalizeTitle = (title) => String(title || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .trim()
      .toUpperCase();
    const baseWorkshops = ['EVALUA', 'INSPIRA', 'INNOVA', 'TRANSFORMA'];
    const rotationByGroup = [
      ['EVALUA', 'INSPIRA', 'INNOVA'],
      ['INSPIRA', 'EVALUA', 'TRANSFORMA'],
      ['INNOVA', 'TRANSFORMA', 'INSPIRA'],
      ['TRANSFORMA', 'INNOVA', 'EVALUA'],
    ];
    const assignedBaseWorkshop = assignments
      .map((assignment) => baseWorkshops.indexOf(normalizeTitle(assignment.title)))
      .find((group) => group >= 0);
    let groupIndex = assignedBaseWorkshop;
    if (groupIndex === undefined) {
      const [users] = await pool.query(
        `SELECT g.name AS group_name
         FROM users u
         LEFT JOIN workshop_groups g ON g.id = u.group_id
         WHERE u.id = ?`,
        [req.user.id]
      );
      const match = /^grupo ([a-d])$/i.exec(users[0]?.group_name || '');
      groupIndex = match ? match[1].toUpperCase().charCodeAt(0) - 65 : null;
    }
    const workshopsByTitle = new Map(
      rows.map((row) => [normalizeTitle(row.title), row])
    );
    const workshops = [];
    if (groupIndex !== null && groupIndex >= 0 && groupIndex < rotationByGroup.length) {
      for (let dayIndex = 0; dayIndex < rotationByGroup[groupIndex].length; dayIndex += 1) {
        const row = workshopsByTitle.get(rotationByGroup[groupIndex][dayIndex]);
        if (!row) continue;
        workshops.push({
          id: row.id,
          title: row.title,
          capacity: row.capacity,
          address: row.address,
          room: row.room,
          dayTimes: parseDayTimes(row),
          rotationDay: dayIndex,
          teachers: [],
        });
      }
    }
    return res.json({
      workshops,
    });
  } catch (error) {
    console.error('Error al consultar mis talleres:', error);
    return res.status(500).json({ message: 'No se pudieron cargar tus talleres' });
  }
});

app.get('/api/admin/users', authMiddleware, requireRole('admin'), async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, name, email, role, group_id, password_setup_required, created_at FROM users ORDER BY created_at DESC'
    );
    return res.json({ users });
  } catch (error) {
    console.error('Error al consultar usuarios para administración:', error);
    return res.status(500).json({ message: 'No se pudo cargar la lista de usuarios' });
  }
});

app.put('/api/admin/users/:id/group', authMiddleware, requireRole('admin'), async (req, res) => {
  const userId = Number(req.params.id);
  const groupName = typeof req.body.groupName === 'string'
    ? req.body.groupName.trim().replace(/\s+/g, ' ')
    : '';
  if (!Number.isInteger(userId) || userId < 1 || !/^Grupo [A-D]$/i.test(groupName)) {
    return res.status(400).json({ message: 'Usuario y grupo válidos son obligatorios' });
  }
  try {
    const [groups] = await pool.query(
      'SELECT id, name FROM workshop_groups WHERE LOWER(TRIM(name)) = LOWER(?)',
      [groupName]
    );
    if (groups.length === 0) {
      return res.status(404).json({ message: `No existe ${groupName}` });
    }
    const [users] = await pool.query(
      'SELECT id FROM users WHERE id = ?',
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    const [result] = await pool.query(
      'UPDATE users SET group_id = ? WHERE id = ?',
      [groups[0].id, userId]
    );
    await pool.query(
      `UPDATE workshop_groups g
       LEFT JOIN (
         SELECT group_id, COUNT(*) AS total
         FROM users
         WHERE group_id IS NOT NULL
         GROUP BY group_id
       ) counts ON counts.group_id = g.id
       SET g.member_count = COALESCE(counts.total, 0)`
    );
    return res.json({
      message: `${groups[0].name} asignado correctamente`,
      updated: result.affectedRows > 0,
    });
  } catch (error) {
    console.error('Error al asignar grupo al usuario:', error);
    return res.status(500).json({ message: 'No se pudo asignar el grupo' });
  }
});

const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const TIME_PATTERN = /^([01]\d|2[0-3]):[0-5]\d$/;

function isValidCalendarDate(value) {
  if (typeof value !== 'string' || !DATE_PATTERN.test(value)) return false;
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.toISOString().slice(0, 10) === value;
}

function parseDayTimes(row) {
  try {
    const parsed = JSON.parse(row.day_times || 'null');
    if (Array.isArray(parsed) && parsed.length >= 1) return parsed;
  } catch (_) {
    // Se usa el horario único anterior.
  }
  if (row.start_time && row.end_time) {
    return [{ date: '', startTime: row.start_time, endTime: row.end_time }];
  }
  return [];
}

function normalizeDayTimes(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 20) return null;
  const result = [];
  for (const item of value) {
    const date = typeof item?.date === 'string' ? item.date.trim() : '';
    const startTime = typeof item?.startTime === 'string' ? item.startTime.trim() : '';
    const endTime = typeof item?.endTime === 'string' ? item.endTime.trim() : '';
    if (!DATE_PATTERN.test(date) || Number.isNaN(Date.parse(date)) || !TIME_PATTERN.test(startTime) || !TIME_PATTERN.test(endTime) || startTime >= endTime) {
      return null;
    }

    result.push({ date, startTime, endTime });
  }

  return result;
}

function isTimeWindowOpen(schedule, kind, currentTime) {
  const enabled = kind === 'attendance'
    ? schedule.attendance_enabled
    : schedule.break_enabled;
  if (!enabled) return false;
  const start = kind === 'attendance' ? schedule.attendance_start : schedule.break_start;
  const end = kind === 'attendance' ? schedule.attendance_end : schedule.break_end;
  return currentTime >= start && currentTime < end;
}

async function getAttendanceScheduleStatus(kind) {
  const [schedules] = await pool.query(
    `SELECT DATE_FORMAT(attendance_start, '%H:%i') AS attendance_start,
            DATE_FORMAT(attendance_end, '%H:%i') AS attendance_end,
            DATE_FORMAT(break_start, '%H:%i') AS break_start,
            DATE_FORMAT(break_end, '%H:%i') AS break_end,
            attendance_enabled,
            break_enabled,
            DATE_FORMAT(
              CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', ?),
              '%H:%i'
            ) AS app_clock
     FROM attendance_schedule_windows
     WHERE event_date = DATE(CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', ?))`,
    [appTimezoneOffset, appTimezoneOffset]
  );
  const currentTime = schedules[0]?.app_clock;
  const openSchedule = schedules.find((schedule) =>
    isTimeWindowOpen(schedule, kind, currentTime));
  return {
    configured: schedules.length > 0,
    open: Boolean(openSchedule),
    schedule: openSchedule || schedules[0],
  };
}

app.get('/api/admin/workshops', authMiddleware, requireRole('admin'), async (_req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT w.id, w.title, w.capacity, w.address, w.room, w.start_time, w.end_time, w.day_times,
              u.id AS teacher_id, u.name AS teacher_name,
              u.email AS teacher_email, u.group_id, g.name AS group_name
       FROM workshops w
       LEFT JOIN workshop_teachers wt ON wt.workshop_id = w.id
       LEFT JOIN users u ON u.id = wt.user_id
       LEFT JOIN workshop_groups g ON g.id = u.group_id
       ORDER BY w.title, u.name`
    );
    const workshopsById = new Map();
    for (const row of rows) {
      if (!workshopsById.has(row.id)) {
        workshopsById.set(row.id, {
          id: row.id,
          title: row.title,
          capacity: row.capacity,
          address: row.address,
          room: row.room,
          startTime: row.start_time,
          endTime: row.end_time,
          dayTimes: parseDayTimes(row),
          teachers: [],
        });
      }
      if (row.teacher_id !== null) {
        workshopsById.get(row.id).teachers.push({
          id: row.teacher_id,
          name: row.teacher_name,
          email: row.teacher_email,
          role: 'teacher',
          group_id: row.group_id,
          group_name: row.group_name,
        });
      }
    }
    return res.json({ workshops: [...workshopsById.values()] });
  } catch (error) {
    console.error('Error al consultar talleres:', error);
    return res.status(500).json({ message: 'No se pudo cargar la lista de talleres' });
  }
});

app.post('/api/admin/workshops', authMiddleware, requireRole('admin'), async (req, res) => {
  const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
  const capacity = Number(req.body.capacity);
  const address = typeof req.body.address === 'string' ? req.body.address.trim() : '';
  const room = typeof req.body.room === 'string' ? req.body.room.trim() : '';
  const dayTimes = normalizeDayTimes(req.body.dayTimes);
  if (
    !title ||
    title.length > 150 ||
    !address ||
    address.length > 255 ||
    !room ||
    room.length > 150 ||
    !dayTimes ||
    !Number.isInteger(capacity) ||
    capacity < 1 ||
    capacity > 100000
  ) {
    return res.status(400).json({
      message: 'Indica un título válido y un cupo diario entre 1 y 100000 personas, además de la dirección, el aula/salón y un horario válido (la hora de inicio debe ser anterior a la de fin en cada fecha)',
    });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO workshops (title, capacity, address, room, start_time, end_time, day_times) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [title, capacity, address, room, dayTimes[0].startTime, dayTimes[0].endTime, JSON.stringify(dayTimes)]
    );
    return res.status(201).json({
      message: 'Taller creado correctamente',
      workshop: { id: result.insertId, title, capacity, address, room, startTime: dayTimes[0].startTime, endTime: dayTimes[0].endTime, dayTimes, teachers: [] },
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Ya existe un taller con ese título' });
    }
    console.error('Error al crear taller:', error);
    return res.status(500).json({ message: 'No se pudo crear el taller' });
  }
});

app.put('/api/admin/workshops/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const workshopId = Number(req.params.id);
  const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
  const capacity = Number(req.body.capacity);
  const address = typeof req.body.address === 'string' ? req.body.address.trim() : '';
  const room = typeof req.body.room === 'string' ? req.body.room.trim() : '';
  const dayTimes = normalizeDayTimes(req.body.dayTimes);
  if (
    !Number.isInteger(workshopId) ||
    workshopId < 1 ||
    !title ||
    title.length > 150 ||
    !address ||
    address.length > 255 ||
    !room ||
    room.length > 150 ||
    !dayTimes ||
    !Number.isInteger(capacity) ||
    capacity < 1 ||
    capacity > 100000
  ) {
    return res.status(400).json({
      message: 'Identificador, título y cupo diario válido son obligatorios',
    });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    await connection.query(
      'SELECT id FROM workshop_groups ORDER BY id FOR UPDATE'
    );
    const [workshops] = await connection.query(
      'SELECT id, title FROM workshops WHERE id = ? FOR UPDATE',
      [workshopId]
    );
    if (workshops.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: 'Taller no encontrado' });
    }
    const [usage] = await connection.query(
      `SELECT ra.rotation_date, COALESCE(SUM(g.member_count), 0) AS assigned_count
       FROM workshop_rotation_assignments ra
       JOIN workshop_groups g ON g.id = ra.group_id
       WHERE ra.workshop_id = ?
       GROUP BY ra.rotation_date
       HAVING assigned_count > ?`,
      [workshopId, capacity]
    );
    if (usage.length > 0) {
      await connection.rollback();
      return res.status(409).json({
        message: 'El nuevo cupo es menor que las personas ya asignadas en una fecha',
      });
    }
    await connection.query(
      'UPDATE workshops SET title = ?, capacity = ?, address = ?, room = ?, start_time = ?, end_time = ?, day_times = ? WHERE id = ?',
      [title, capacity, address, room, dayTimes[0].startTime, dayTimes[0].endTime, JSON.stringify(dayTimes), workshopId]
    );
    await connection.commit();
    return res.json({ message: 'Taller actualizado correctamente' });
  } catch (error) {
    await connection.rollback();
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Ya existe un taller con ese título' });
    }
    console.error('Error al actualizar taller:', error);
    return res.status(500).json({ message: 'No se pudo actualizar el taller' });
  } finally {
    connection.release();
  }
});

app.delete('/api/admin/workshops/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const workshopId = Number(req.params.id);
  if (!Number.isInteger(workshopId) || workshopId < 1) {
    return res.status(400).json({ message: 'Identificador de taller inválido' });
  }
  try {
    const [result] = await pool.query(
      'DELETE FROM workshops WHERE id = ?',
      [workshopId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Taller no encontrado' });
    }
    return res.json({ message: 'Taller eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar taller:', error);
    return res.status(500).json({ message: 'No se pudo eliminar el taller' });
  }
});

app.put('/api/admin/workshops/:id/teachers', authMiddleware, requireRole('admin'), async (req, res) => {
  const workshopId = Number(req.params.id);
  const requestedIds = req.body.teacherIds;
  if (
    !Number.isInteger(workshopId) ||
    workshopId < 1 ||
    !Array.isArray(requestedIds) ||
    requestedIds.some((id) => !Number.isInteger(id) || id < 1)
  ) {
    return res.status(400).json({ message: 'Taller o lista de docentes inválidos' });
  }

  const teacherIds = [...new Set(requestedIds)];
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [workshops] = await connection.query(
      'SELECT id FROM workshops WHERE id = ? FOR UPDATE',
      [workshopId]
    );
    if (workshops.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: 'Taller no encontrado' });
    }
    if (teacherIds.length > 0) {
      const [teachers] = await connection.query(
        `SELECT id FROM users WHERE role = 'teacher' AND id IN (${teacherIds.map(() => '?').join(',')})`,
        teacherIds
      );
      if (teachers.length !== teacherIds.length) {
        await connection.rollback();
        return res.status(400).json({
          message: 'Solo se pueden asignar cuentas registradas como docentes',
        });
      }
    }

    const workshopTitle = String(workshops[0].title || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .trim()
      .toUpperCase();
    const groupByWorkshop = {
      EVALUA: 'Grupo A',
      INSPIRA: 'Grupo B',
      INNOVA: 'Grupo C',
      TRANSFORMA: 'Grupo D',
    };
    const targetGroupName = groupByWorkshop[workshopTitle];
    let targetGroupId = null;
    if (targetGroupName) {
      const [groups] = await connection.query(
        'SELECT id FROM workshop_groups WHERE LOWER(TRIM(name)) = LOWER(?)',
        [targetGroupName]
      );
      targetGroupId = groups[0]?.id || null;
    }
    const previousTeacherIds = new Set(
      (await connection.query(
        'SELECT user_id FROM workshop_teachers WHERE workshop_id = ?',
        [workshopId]
      ))[0].map((row) => Number(row.user_id))
    );

    await connection.query(
      'DELETE FROM workshop_teachers WHERE workshop_id = ?',
      [workshopId]
    );
    if (teacherIds.length > 0) {
      await connection.query(
        'INSERT INTO workshop_teachers (workshop_id, user_id) VALUES ?',
        [teacherIds.map((teacherId) => [workshopId, teacherId])]
      );
    }
    if (targetGroupId) {
      if (teacherIds.length > 0) {
        await connection.query(
          `UPDATE users SET group_id = ?
           WHERE role = 'teacher' AND id IN (${teacherIds.map(() => '?').join(',')})`,
          [targetGroupId, ...teacherIds]
        );
      }
      const removedIds = [...previousTeacherIds].filter(
        (teacherId) => !teacherIds.includes(teacherId)
      );
      if (removedIds.length > 0) {
        await connection.query(
          `UPDATE users SET group_id = NULL
           WHERE role = 'teacher' AND group_id = ?
             AND id IN (${removedIds.map(() => '?').join(',')})`,
          [targetGroupId, ...removedIds]
        );
      }
    }
    await connection.commit();
    return res.json({ message: 'Docentes asignados correctamente al taller' });
  } catch (error) {
    await connection.rollback();
    console.error('Error al asignar docentes al taller:', error);
    return res.status(500).json({ message: 'No se pudieron guardar las asignaciones' });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/workshop-groups', authMiddleware, requireRole('admin'), async (_req, res) => {
  try {
    const [groups] = await pool.query(
      'SELECT id, name, member_count FROM workshop_groups ORDER BY name'
    );
    return res.json({ groups });
  } catch (error) {
    console.error('Error al consultar grupos de talleres:', error);
    return res.status(500).json({ message: 'No se pudieron cargar los grupos' });
  }
});

app.post('/api/admin/workshop-groups', authMiddleware, requireRole('admin'), async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const memberCount = Number(req.body.memberCount);
  if (
    !name ||
    name.length > 100 ||
    !Number.isInteger(memberCount) ||
    memberCount < 1 ||
    memberCount > 100000
  ) {
    return res.status(400).json({
      message: 'Indica un nombre y una cantidad de personas válida para el grupo',
    });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO workshop_groups (name, member_count) VALUES (?, ?)',
      [name, memberCount]
    );
    return res.status(201).json({
      message: 'Grupo creado correctamente',
      group: { id: result.insertId, name, memberCount },
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Ya existe un grupo con ese nombre' });
    }
    console.error('Error al crear grupo de taller:', error);
    return res.status(500).json({ message: 'No se pudo crear el grupo' });
  }
});

app.put('/api/admin/workshop-groups/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const groupId = Number(req.params.id);
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const memberCount = Number(req.body.memberCount);
  if (
    !Number.isInteger(groupId) ||
    groupId < 1 ||
    !name ||
    name.length > 100 ||
    !Number.isInteger(memberCount) ||
    memberCount < 1 ||
    memberCount > 100000
  ) {
    return res.status(400).json({
      message: 'Identificador, nombre y cantidad de personas válidos son obligatorios',
    });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [lockedGroups] = await connection.query(
      'SELECT id, member_count FROM workshop_groups ORDER BY id FOR UPDATE'
    );
    const group = lockedGroups.find((item) => item.id === groupId);
    if (!group) {
      await connection.rollback();
      return res.status(404).json({ message: 'Grupo no encontrado' });
    }

    await connection.query('SELECT id FROM workshops ORDER BY id FOR UPDATE');
    const [usage] = await connection.query(
      `SELECT ra.rotation_date, w.title, w.capacity,
              SUM(g.member_count) - ? + ? AS updated_count
       FROM workshop_rotation_assignments ra
       JOIN workshop_groups g ON g.id = ra.group_id
       JOIN workshops w ON w.id = ra.workshop_id
       WHERE ra.workshop_id IN (
         SELECT workshop_id FROM workshop_rotation_assignments WHERE group_id = ?
       )
       GROUP BY ra.rotation_date, ra.workshop_id, w.title, w.capacity
       HAVING SUM(CASE WHEN g.id = ? THEN 1 ELSE 0 END) > 0
          AND updated_count > w.capacity`,
      [group.member_count, memberCount, groupId, groupId]
    );
    if (usage.length > 0) {
      await connection.rollback();
      return res.status(409).json({
        message: `No se puede aumentar el grupo: el taller "${usage[0].title}" quedaría por encima del cupo en una fecha asignada`,
      });
    }
    await connection.query(
      'UPDATE workshop_groups SET name = ?, member_count = ? WHERE id = ?',
      [name, memberCount, groupId]
    );
    await connection.commit();
    return res.json({ message: 'Grupo actualizado correctamente' });
  } catch (error) {
    await connection.rollback();
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Ya existe un grupo con ese nombre' });
    }
    console.error('Error al actualizar grupo de taller:', error);
    return res.status(500).json({ message: 'No se pudo actualizar el grupo' });
  } finally {
    connection.release();
  }
});

app.delete('/api/admin/workshop-groups/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const groupId = Number(req.params.id);
  if (!Number.isInteger(groupId) || groupId < 1) {
    return res.status(400).json({ message: 'Identificador de grupo inválido' });
  }
  try {
    const [result] = await pool.query(
      'DELETE FROM workshop_groups WHERE id = ?',
      [groupId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Grupo no encontrado' });
    }
    return res.json({ message: 'Grupo eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar grupo de taller:', error);
    return res.status(500).json({ message: 'No se pudo eliminar el grupo' });
  }
});

app.get('/api/admin/workshop-rotation', authMiddleware, requireRole('admin'), async (_req, res) => {
  try {
    const [assignments] = await pool.query(
      `SELECT DATE_FORMAT(ra.rotation_date, '%Y-%m-%d') AS rotation_date,
              g.id AS group_id, g.name AS group_name,
              g.member_count, w.id AS workshop_id, w.title AS workshop_title,
              w.capacity,
              u.id AS teacher_id, u.name AS teacher_name, u.email AS teacher_email
       FROM workshop_rotation_assignments ra
       JOIN workshop_groups g ON g.id = ra.group_id
       JOIN workshops w ON w.id = ra.workshop_id
       LEFT JOIN workshop_teachers wt ON wt.workshop_id = w.id
       LEFT JOIN users u ON u.id = wt.user_id
       ORDER BY ra.rotation_date, g.name, u.name`
    );
    const entries = new Map();
    for (const row of assignments) {
      const date = String(row.rotation_date).slice(0, 10);
      const key = `${date}:${row.group_id}`;
      if (!entries.has(key)) {
        entries.set(key, {
          date,
          groupId: row.group_id,
          groupName: row.group_name,
          memberCount: row.member_count,
          workshopId: row.workshop_id,
          workshopTitle: row.workshop_title,
          capacity: row.capacity,
          teachers: [],
        });
      }
      if (row.teacher_id !== null) {
        entries.get(key).teachers.push({
          id: row.teacher_id,
          name: row.teacher_name,
          email: row.teacher_email,
          role: 'teacher',
        });
      }
    }
    return res.json({ assignments: [...entries.values()] });
  } catch (error) {
    console.error('Error al consultar rotación de talleres:', error);
    return res.status(500).json({ message: 'No se pudo cargar la rotación' });
  }
});

app.post('/api/admin/workshop-rotation', authMiddleware, requireRole('admin'), async (req, res) => {
  const startDate = typeof req.body.startDate === 'string' ? req.body.startDate : '';
  const dateMatch = /^(\d{4})-(\d{2})-(\d{2})$/.exec(startDate);
  const selections = req.body.assignments;
  if (!dateMatch || !Array.isArray(selections) || selections.length > 10000) {
    return res.status(400).json({
      message: 'La fecha de inicio y las asignaciones son obligatorias',
    });
  }

  const parsedDate = new Date(Date.UTC(
    Number(dateMatch[1]),
    Number(dateMatch[2]) - 1,
    Number(dateMatch[3])
  ));
  if (parsedDate.toISOString().slice(0, 10) !== startDate) {
    return res.status(400).json({ message: 'La fecha de inicio no es válida' });
  }

  const endDate = new Date(parsedDate);
  endDate.setUTCDate(endDate.getUTCDate() + 3);
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [groups] = await connection.query(
      'SELECT id, member_count FROM workshop_groups ORDER BY id FOR UPDATE'
    );
    const [workshops] = await connection.query(
      'SELECT id, title, capacity FROM workshops ORDER BY id FOR UPDATE'
    );
    if (groups.length === 0) {
      await connection.rollback();
      return res.status(400).json({ message: 'Primero crea al menos un grupo' });
    }
    if (workshops.length === 0) {
      await connection.rollback();
      return res.status(400).json({ message: 'Primero crea al menos un taller' });
    }

    const groupsById = new Map(groups.map((group) => [group.id, group]));
    const workshopsById = new Map(workshops.map((workshop) => [workshop.id, workshop]));
    const seenGroupDays = new Set();
    const seenGroupWorkshops = new Set();
    const occupancyByDateWorkshop = new Map();
    const dbAssignments = [];

    for (const selection of selections) {
      const groupId = Number(selection?.groupId);
      const workshopId = Number(selection?.workshopId);
      const dayIndex = Number(selection?.dayIndex);
      if (
        !Number.isInteger(groupId) ||
        !groupsById.has(groupId) ||
        !Number.isInteger(workshopId) ||
        !workshopsById.has(workshopId) ||
        !Number.isInteger(dayIndex) ||
        dayIndex < 0 ||
        dayIndex > 2
      ) {
        await connection.rollback();
        return res.status(400).json({ message: 'Hay asignaciones inválidas' });
      }
      const groupDayKey = `${groupId}:${dayIndex}`;
      const groupWorkshopKey = `${groupId}:${workshopId}`;
      if (seenGroupDays.has(groupDayKey)) {
        await connection.rollback();
        return res.status(400).json({
          message: 'Cada grupo debe tener solo un taller por día',
        });
      }
      const group = groupsById.get(groupId);
      if (group.member_count < 1) {
        await connection.rollback();
        return res.status(400).json({
          message: `Registra cuántas personas tiene el grupo "${group.name}" antes de asignarlo`,
        });
      }
      if (seenGroupWorkshops.has(groupWorkshopKey)) {
        await connection.rollback();
        return res.status(400).json({
          message: 'Cada grupo debe visitar un taller distinto en cada día',
        });
      }
      seenGroupDays.add(groupDayKey);
      seenGroupWorkshops.add(groupWorkshopKey);

      const rotationDate = new Date(parsedDate);
      rotationDate.setUTCDate(rotationDate.getUTCDate() + dayIndex);
      const date = rotationDate.toISOString().slice(0, 10);
      const occupancyKey = `${date}:${workshopId}`;
      occupancyByDateWorkshop.set(
        occupancyKey,
        (occupancyByDateWorkshop.get(occupancyKey) ?? 0) + group.member_count
      );
      dbAssignments.push([
        date,
        groupId,
        workshopId,
      ]);
    }

    for (const [key, assignedCount] of occupancyByDateWorkshop) {
      const [, workshopId] = key.split(':');
      const workshop = workshopsById.get(Number(workshopId));
      if (assignedCount > workshop.capacity) {
        await connection.rollback();
        return res.status(409).json({
          message: `El taller "${workshop.title}" está completado para esa fecha: cupo ${workshop.capacity}, asignadas ${assignedCount} personas`,
        });
      }
    }

    await connection.query(
      'DELETE FROM workshop_rotation_assignments WHERE rotation_date >= ? AND rotation_date < ?',
      [startDate, endDate.toISOString().slice(0, 10)]
    );
    if (dbAssignments.length > 0) {
      await connection.query(
        `INSERT INTO workshop_rotation_assignments
           (rotation_date, group_id, workshop_id)
         VALUES ?`,
        [dbAssignments]
      );
    }
    await connection.commit();

    return res.json({
      message: 'Se guardó la programación y se actualizaron los cupos restantes.',
      assignmentCount: dbAssignments.length,
    });
  } catch (error) {
    await connection.rollback();
    console.error('Error al guardar programación manual de talleres:', error);
    return res.status(500).json({ message: 'No se pudo guardar la programación' });
  } finally {
    connection.release();
  }
});

app.post('/api/admin/users/:id/invitation', authMiddleware, requireRole('admin'), async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId) || userId < 1) {
    return res.status(400).json({ message: 'Identificador de usuario inválido' });
  }
  if (!emailServiceConfigured) {
    return res.status(503).json({ message: 'El servicio de correo no está configurado' });
  }

  try {
    const [users] = await pool.query(
      'SELECT role FROM users WHERE id = ?',
      [userId]
    );
    if (users.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    if (users[0].role === 'admin') {
      return res.status(400).json({ message: 'No puedes enviar invitaciones a administradores' });
    }

    const user = await sendPasswordSetupInvitation(userId);
    return res.json({
      message: `Se envió la invitación a ${user.email}`,
    });
  } catch (error) {
    if (error.code === 'PASSWORD_ALREADY_CONFIGURED') {
      return res.status(409).json({ message: error.message });
    }
    console.error('Error al enviar invitación a docente:', error);
    return res.status(502).json({
      message: 'No se pudo enviar la invitación por correo',
    });
  }
});

app.post('/api/admin/users/invitations', authMiddleware, requireRole('admin'), async (_req, res) => {
  if (!emailServiceConfigured) {
    return res.status(503).json({ message: 'El servicio de correo no está configurado' });
  }

  try {
    const [teachers] = await pool.query(
      `SELECT id, name, email FROM users
       WHERE role = 'teacher' AND password_setup_required = 1
       ORDER BY created_at`
    );
    const results = [];
    for (const teacher of teachers) {
      try {
        await sendPasswordSetupInvitation(teacher.id);
        results.push({
          id: teacher.id,
          name: teacher.name,
          email: teacher.email,
          status: 'sent',
        });
      } catch (error) {
        console.error(`Error al enviar invitación a ${teacher.email}:`, error);
        results.push({
          id: teacher.id,
          name: teacher.name,
          email: teacher.email,
          status: 'error',
          message: 'No se pudo enviar la invitación',
        });
      }
    }

    const sent = results.filter((result) => result.status === 'sent').length;
    const failed = results.length - sent;
    return res.status(failed > 0 ? 207 : 200).json({
      message: `Se enviaron ${sent} de ${results.length} invitaciones a docentes`,
      sent,
      failed,
      results,
    });
  } catch (error) {
    console.error('Error al enviar invitaciones grupales:', error);
    return res.status(500).json({
      message: 'No se pudieron procesar las invitaciones grupales',
    });
  }
});

app.post('/api/admin/users', authMiddleware, requireRole('admin'), async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body.email === 'string' ? req.body.email.trim() : '';
  const role = req.body.role === 'attendant' ? 'attendant' : 'teacher';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (password && (password.length < 8 || password.length > 128)) {
    return res.status(400).json({ message: 'La contraseña debe tener entre 8 y 128 caracteres' });
  }
  if (
    !name ||
    name.length > 100 ||
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ||
    email.length > 150
  ) {
    return res.status(400).json({
      message: 'El nombre y un correo válido son obligatorios',
    });
  }
  if (!emailServiceConfigured) {
    return res.status(503).json({ message: 'El servicio de correo no está configurado' });
  }

  try {
    const user = await createAdminUser({ name, email, role, password });
    return res.status(201).json({
      message: 'Usuario creado; se envió un enlace para configurar su contraseña',
      user,
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Ya existe una cuenta con ese correo' });
    }
    console.error('Error al crear usuario desde administración:', error);
    return res.status(502).json({
      message: 'No se pudo crear la cuenta o enviar el correo de configuración',
    });
  }
});

app.post(
  '/api/admin/users/import',
  authMiddleware,
  requireRole('admin'),
  previewUpload.single('file'),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: 'Selecciona un archivo DOCX con una tabla de usuarios' });
    }
    const validationMessage = getDocxValidationError(req.file.originalname, req.file.buffer);
    if (validationMessage) {
      return res.status(415).json({ message: validationMessage });
    }
    let rows;
    try {
      const document = await mammoth.convertToHtml({ buffer: req.file.buffer });
      const $ = cheerio.load(document.value);
      const table = $('table').first();
      rows = table.find('tr').toArray().map((row) =>
        $(row).children('th, td').map((_, cell) => $(cell).text().trim()).get()
      ).filter((row) => row.some(Boolean));
    } catch (error) {
      console.error('Error al leer tabla de usuarios desde Word:', error);
      return res.status(422).json({ message: 'No se pudo interpretar la tabla del documento Word' });
    }

    if (!rows || rows.length < 2) {
      return res.status(400).json({
        message: 'El Word debe incluir una tabla con encabezados y al menos un usuario',
      });
    }
    if (rows.length > 501) {
      return res.status(400).json({ message: 'El Word no puede contener más de 500 usuarios' });
    }

    const normalizeHeader = (value) => value
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .trim()
      .toLowerCase();
    const headers = rows[0].map(normalizeHeader);
    const nameIndex = headers.findIndex((header) => ['nombre', 'name'].includes(header));
    const emailIndex = headers.findIndex((header) =>
      [
        'correo',
        'correos',
        'email',
        'correo electronico',
        'correos electronico',
        'correos electronicos',
        'e-mail',
      ].includes(header)
    );
    if (nameIndex < 0 || emailIndex < 0) {
      return res.status(400).json({
        message: 'La primera fila de la tabla debe tener los encabezados "Nombre" y "Correo electrónico"',
      });
    }

    const results = [];
    for (const [index, row] of rows.slice(1).entries()) {
      const name = (row[nameIndex] || '').trim();
      const email = (row[emailIndex] || '').trim();
      let message = '';

      if (!name || name.length > 100) {
        message = 'El nombre es obligatorio y no puede superar 100 caracteres';
      } else if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 150) {
        message = 'El correo electrónico no es válido';
      } else {
        try {
          const imported = await importTeacher({ name, email });
          results.push({ row: index + 2, ...imported });
          continue;
        } catch (error) {
          console.error(`Error al importar docente en fila ${index + 2}:`, error);
          message = 'No se pudo importar el docente';
        }
      }

      results.push({ row: index + 2, name, email, status: 'error', message });
    }

    const created = results.filter((result) => result.status === 'created').length;
    const updated = results.filter((result) => result.status === 'updated').length;
    const alreadyRegistered = results.filter(
      (result) => result.status === 'already_registered'
    ).length;
    const failed = results.filter((result) => result.status === 'error').length;
    return res.status(failed > 0 ? 207 : 201).json({
      message: `Nuevos: ${created}; actualizados: ${updated}; ya registrados: ${alreadyRegistered}; errores: ${failed}. No se enviaron correos.`,
      created,
      updated,
      alreadyRegistered,
      failed,
      results,
    });
  }
);

app.put('/api/admin/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const userId = Number(req.params.id);
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const newPassword = typeof req.body.password === 'string' ? req.body.password : '';
  if (newPassword && (newPassword.length < 8 || newPassword.length > 128)) {
    return res.status(400).json({ message: 'La contraseña debe tener entre 8 y 128 caracteres' });
  }

  if (
    !Number.isInteger(userId) ||
    userId < 1 ||
    !name ||
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)
  ) {
    return res.status(400).json({ message: 'Nombre y correo válidos son obligatorios' });
  }

  try {
    const [currentUsers] = await pool.query('SELECT role FROM users WHERE id = ?', [userId]);
    if (currentUsers.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    await pool.query(
      'UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?',
      [name, email, roleForEmail(email, currentUsers[0].role), userId]
    );
    if (newPassword) {
      await pool.query(
        'UPDATE users SET password = ?, password_setup_required = 0 WHERE id = ?',
        [await bcrypt.hash(newPassword, 10), userId]
      );
      await pool.query(
        'UPDATE password_setup_tokens SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL',
        [userId]
      );
    }
    const [users] = await pool.query(
      'SELECT id, name, email, role FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    return res.json({
      message: 'Usuario actualizado correctamente',
      user: users[0],
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Ya existe una cuenta con ese correo' });
    }
    console.error('Error al actualizar usuario:', error);
    return res.status(500).json({ message: 'No se pudo actualizar el usuario' });
  }
});

app.delete('/api/admin/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId) || userId < 1) {
    return res.status(400).json({ message: 'Identificador de usuario inválido' });
  }

  if (Number(req.user.id) === userId) {
    return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta' });
  }

  try {
    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    return res.json({ message: 'Usuario eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar usuario:', error);
    return res.status(500).json({ message: 'No se pudo eliminar el usuario' });
  }
});

async function sendActivities(_req, res) {
  try {
    const [rows] = await pool.query(`
      SELECT
        a.id,
        a.activity,
        a.title,
        a.description,
        a.date,
        a.time,
        a.time_end,
        MAX(a.responsible) AS responsible,
        MAX(a.place) AS place,
        a.modality,
        at.name AS type_name,
        a.file_name,
        a.file_path,
        a.created_at,
        GROUP_CONCAT(s.name ORDER BY s.name SEPARATOR ', ') AS speakers
      FROM activities a
      LEFT JOIN activity_types at ON at.id = a.activity_type_id
      LEFT JOIN activity_speakers aps ON aps.activity_id = a.id
      LEFT JOIN speakers s ON s.id = aps.speaker_id
      GROUP BY a.id, a.activity, a.title, a.description, a.date, a.time, a.time_end, a.modality,
               at.name, a.file_name, a.file_path, a.created_at
      ORDER BY a.date ASC, a.time ASC, a.id ASC
    `);
    if (_req.user?.role === 'teacher') {
      const [workshops] = await pool.query(
        `SELECT w.id, w.title, w.address, w.room, w.day_times
         FROM workshops w
         INNER JOIN workshop_teachers wt ON wt.workshop_id = w.id
         WHERE wt.user_id = ?`,
        [_req.user.id]
      );
      for (const workshop of workshops) {
        const dayTimes = parseDayTimes(workshop);
        dayTimes.forEach((dayTime, index) => {
          rows.push({
            id: -((Number(workshop.id) * 100) + index + 1),
            activity: workshop.title,
            title: workshop.title,
            description: '',
            date: dayTime.date,
            time: dayTime.startTime,
            time_end: dayTime.endTime,
            responsible: 'Taller',
            place: [workshop.address, workshop.room].filter(Boolean).join(' · '),
            modality: 'Taller',
            type_name: 'Taller',
            file_name: '',
            file_path: '',
            created_at: null,
            speakers: null,
          });
        });
      }
      rows.sort((left, right) => {
        const dateComparison = String(left.date).localeCompare(String(right.date));
        if (dateComparison !== 0) return dateComparison;
        return String(left.time).localeCompare(String(right.time));
      });
    }
    return res.json({ activities: rows });
  } catch (error) {
    console.error('Error al consultar actividades:', error);
    return res.status(500).json({ message: 'No se pudo cargar la lista de actividades' });
  }
}

app.get('/api/activities', authMiddleware, sendActivities);
app.get('/api/admin/activities', authMiddleware, requireRole('admin'), sendActivities);

async function sendContentSections(_req, res) {
  try {
    const [rows] = await pool.query(
      `SELECT id, title, body, image_path AS imagePath,
              video_path AS videoPath, video_url AS videoUrl,
              display_order AS displayOrder
       FROM content_sections ORDER BY display_order ASC, id DESC`
    );
    return res.json({ sections: rows });
  } catch (error) {
    console.error('Error al consultar secciones:', error);
    return res.status(500).json({ message: 'No se pudieron cargar las secciones' });
  }
}

app.get('/api/sections', authMiddleware, sendContentSections);
app.get('/api/admin/sections', authMiddleware, requireRole('admin'), sendContentSections);

app.post(
  '/api/admin/sections',
  authMiddleware,
  requireRole('admin'),
  sectionUpload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]),
  async (req, res) => {
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const body = typeof req.body.body === 'string' ? req.body.body.trim() : '';
    const videoUrl = typeof req.body.videoUrl === 'string' ? req.body.videoUrl.trim() : '';
    const image = req.files?.image?.[0];
    const video = req.files?.video?.[0];
    if (videoUrl && !/^https?:\/\//i.test(videoUrl)) {
      return res.status(400).json({
        message: 'Agrega un título, texto, imagen o video. La URL del video debe ser válida.',
      });
    }
    try {
      const uploadedImage = image
        ? await uploadToCloudinary(image.buffer, {
            folder: `${cloudinaryFolder}/sections`,
            resourceType: 'image',
          })
        : null;
      const uploadedVideo = video
        ? await uploadToCloudinary(video.buffer, {
            folder: `${cloudinaryFolder}/sections`,
            resourceType: 'video',
          })
        : null;
      const [result] = await pool.query(
        `INSERT INTO content_sections
         (title, body, image_path, video_path, video_url,
          image_cloudinary_id, video_cloudinary_id, display_order)
         VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT MIN(display_order) - 1
           FROM (SELECT display_order FROM content_sections) AS current_sections), 0))`,
        [
          title,
          body,
          uploadedImage?.secure_url || null,
          uploadedVideo?.secure_url || null,
          videoUrl || null,
          uploadedImage?.public_id || null,
          uploadedVideo?.public_id || null,
        ]
      );
      return res.status(201).json({ id: result.insertId });
    } catch (error) {
      console.error('Error al crear sección:', error);
      return res.status(500).json({ message: 'No se pudo crear la sección' });
    }
  }
);

app.put(
  '/api/admin/sections/:id',
  authMiddleware,
  requireRole('admin'),
  sectionUpload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]),
  async (req, res) => {
    const id = Number(req.params.id);
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const body = typeof req.body.body === 'string' ? req.body.body.trim() : '';
    const videoUrl = typeof req.body.videoUrl === 'string' ? req.body.videoUrl.trim() : '';
    const image = req.files?.image?.[0];
    const video = req.files?.video?.[0];
    const removeImage = req.body.removeImage === 'true';
    const removeVideo = req.body.removeVideo === 'true';
    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ message: 'Sección inválida' });
    }
    if (videoUrl && !/^https?:\/\//i.test(videoUrl)) {
      return res.status(400).json({ message: 'La URL del video no es válida' });
    }
    try {
      const [rows] = await pool.query(
        `SELECT image_path, video_path, image_cloudinary_id,
                video_cloudinary_id
         FROM content_sections WHERE id = ?`,
        [id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ message: 'Sección no encontrada' });
      }
      const uploadedImage = image
        ? await uploadToCloudinary(image.buffer, {
            folder: `${cloudinaryFolder}/sections`,
            resourceType: 'image',
          })
        : null;
      const uploadedVideo = video
        ? await uploadToCloudinary(video.buffer, {
            folder: `${cloudinaryFolder}/sections`,
            resourceType: 'video',
          })
        : null;
      const nextImagePath = image
        ? uploadedImage.secure_url
        : removeImage
        ? null
        : rows[0].image_path;
      const nextVideoPath = video
        ? uploadedVideo.secure_url
        : removeVideo
        ? null
        : rows[0].video_path;
      await pool.query(
        `UPDATE content_sections
         SET title = ?, body = ?, image_path = ?, video_path = ?, video_url = ?
             , image_cloudinary_id = ?, video_cloudinary_id = ?
         WHERE id = ?`,
        [
          title,
          body,
          nextImagePath,
          nextVideoPath,
          removeVideo ? null : videoUrl || null,
          image ? uploadedImage.public_id : removeImage ? null : rows[0].image_cloudinary_id,
          video ? uploadedVideo.public_id : removeVideo ? null : rows[0].video_cloudinary_id,
          id,
        ]
      );
      if (image || removeImage) {
        await deleteCloudinaryAsset(rows[0].image_cloudinary_id, 'image');
      }
      if (video || removeVideo) {
        await deleteCloudinaryAsset(rows[0].video_cloudinary_id, 'video');
      }
      return res.json({ message: 'Sección actualizada correctamente' });
    } catch (error) {
      console.error('Error al actualizar sección:', error);
      return res.status(500).json({ message: 'No se pudo actualizar la sección' });
    }
  }
);

app.put('/api/admin/sections/:id/order', authMiddleware, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const direction = req.body.direction;
  if (!Number.isInteger(id) || id < 1 || !['up', 'down'].includes(direction)) {
    return res.status(400).json({ message: 'Sección y dirección válidas son obligatorias' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [currentRows] = await connection.query(
      'SELECT id, display_order FROM content_sections WHERE id = ? FOR UPDATE',
      [id]
    );
    if (currentRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: 'Sección no encontrada' });
    }
    const comparator = direction === 'up' ? '<' : '>';
    const sort = direction === 'up' ? 'DESC' : 'ASC';
    const [neighborRows] = await connection.query(
      `SELECT id, display_order
       FROM content_sections
       WHERE display_order ${comparator} ?
       ORDER BY display_order ${sort}, id ${sort}
       LIMIT 1
       FOR UPDATE`,
      [currentRows[0].display_order]
    );
    if (neighborRows.length === 0) {
      await connection.commit();
      return res.json({ message: 'La sección ya está en ese extremo' });
    }
    await connection.query(
      'UPDATE content_sections SET display_order = ? WHERE id = ?',
      [neighborRows[0].display_order, id]
    );
    await connection.query(
      'UPDATE content_sections SET display_order = ? WHERE id = ?',
      [currentRows[0].display_order, neighborRows[0].id]
    );
    await connection.commit();
    return res.json({ message: 'Orden actualizado correctamente' });
  } catch (error) {
    await connection.rollback();
    console.error('Error al actualizar orden de secciones:', error);
    return res.status(500).json({ message: 'No se pudo actualizar el orden' });
  } finally {
    connection.release();
  }
});

app.delete('/api/admin/sections/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ message: 'Sección inválida' });
  }
  try {
    const [rows] = await pool.query(
      `SELECT image_path, video_path, image_cloudinary_id,
              video_cloudinary_id
       FROM content_sections WHERE id = ?`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'Sección no encontrada' });
    await pool.query('DELETE FROM content_sections WHERE id = ?', [id]);
    await deleteCloudinaryAsset(rows[0].image_cloudinary_id, 'image');
    await deleteCloudinaryAsset(rows[0].video_cloudinary_id, 'video');
    for (const storedPath of [rows[0].image_path, rows[0].video_path].filter(
      (value) => value && value.startsWith('/uploads/')
    )) {
      await fs.promises.unlink(path.join(uploadsDir, path.basename(storedPath))).catch(() => {});
    }
    return res.json({ message: 'Sección eliminada' });
  } catch (error) {
    console.error('Error al eliminar sección:', error);
    return res.status(500).json({ message: 'No se pudo eliminar la sección' });
  }
});

app.post('/api/admin/activities/batch', authMiddleware, requireRole('admin'), upload.single('file'), async (req, res) => {
  const discardUpload = async () => {
    if (req.file?.path) {
      try {
        await fs.promises.unlink(req.file.path);
      } catch {}
    }
  };

  if (!req.file) {
    return res.status(400).json({ message: 'Debes adjuntar el documento DOCX de la agenda' });
  }

  let activities;
  try {
    activities = JSON.parse(req.body.activities || '');
  } catch {
    await discardUpload();
    return res.status(400).json({ message: 'La lista de actividades no tiene un formato válido' });
  }

  if (!Array.isArray(activities) || activities.length === 0 || activities.length > 500) {
    await discardUpload();
    return res.status(400).json({ message: 'La agenda debe contener entre 1 y 500 actividades' });
  }

  const validDate = (value) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const date = new Date(`${value}T00:00:00.000Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
  };
  const normalizedActivities = activities.map((item) => {
    const activity = typeof item?.activity === 'string' ? item.activity.trim() : '';
    const date = typeof item?.date === 'string' ? item.date.trim() : '';
    const time = typeof item?.time === 'string' ? item.time.trim() : '';
    const timeEnd = typeof item?.timeEnd === 'string' && item.timeEnd.trim()
      ? item.timeEnd.trim()
      : null;
    const responsible = typeof item?.responsible === 'string' ? item.responsible.trim() : '';
    const place = typeof item?.place === 'string' ? item.place.trim() : '';
    const modality = typeof item?.modality === 'string' ? item.modality.trim() : '';
    return { activity, date, time, timeEnd, responsible, place, modality };
  });
  const invalidActivityIndex = normalizedActivities.findIndex((item) =>
    !item.activity ||
    Buffer.byteLength(item.activity, 'utf8') > 60000 ||
    !validDate(item.date) ||
    !/^([01]\d|2[0-3]):[0-5]\d$/.test(item.time) ||
    (item.timeEnd !== null && !/^([01]\d|2[0-3]):[0-5]\d$/.test(item.timeEnd)) ||
    Buffer.byteLength(item.responsible, 'utf8') > 60000 ||
    Buffer.byteLength(item.place, 'utf8') > 60000 ||
    item.modality.length > 100
  );
  if (invalidActivityIndex !== -1) {
    const item = normalizedActivities[invalidActivityIndex];
    let reason = 'la fecha o la hora no es válida';
    if (!item.activity) {
      reason = 'falta el nombre de la actividad';
    } else if (Buffer.byteLength(item.activity, 'utf8') > 60000) {
      reason = 'el texto de la actividad supera el máximo permitido';
    } else if (
      Buffer.byteLength(item.responsible, 'utf8') > 60000 ||
      Buffer.byteLength(item.place, 'utf8') > 60000
    ) {
      reason = 'el responsable o el lugar supera el máximo permitido';
    } else if (item.modality.length > 100) {
      reason = 'la modalidad supera los 100 caracteres';
    }
    await discardUpload();
    return res.status(400).json({
      message: `La actividad ${invalidActivityIndex + 1} no se puede guardar: ${reason}`,
    });
  }

  let fileBuffer;
  try {
    fileBuffer = await fs.promises.readFile(req.file.path);
  } catch {
    await discardUpload();
    return res.status(400).json({ message: 'No se pudo leer el documento DOCX' });
  }
  const validationMessage = getDocxValidationError(req.file.originalname, fileBuffer);
  if (validationMessage) {
    await discardUpload();
    return res.status(415).json({ message: validationMessage });
  }

  const title = path.basename(req.file.originalname, path.extname(req.file.originalname))
    .slice(0, 200) || 'Agenda';
  let uploadedDocument;
  try {
    uploadedDocument = await uploadToCloudinary(fileBuffer, {
      folder: `${cloudinaryFolder}/activities`,
      resourceType: 'raw',
      publicId: `${path.basename(req.file.originalname, path.extname(req.file.originalname))}_${Date.now()}`,
    });
  } catch (error) {
    await discardUpload();
    console.error('Error al subir agenda a Cloudinary:', error);
    return res.status(502).json({ message: 'No se pudo almacenar la agenda' });
  }

  const filePath = uploadedDocument.secure_url;
  const fileCloudinaryId = uploadedDocument.public_id;
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const savedActivities = [];

    // Una agenda nueva reemplaza todas las actividades cargadas desde Word.
    await connection.query(
      'DELETE FROM activities WHERE file_name = ? OR (file_name IS NOT NULL AND activity_type_id IS NULL)',
      [req.file.originalname]
    );

    for (let index = 0; index < normalizedActivities.length; index += 1) {
      const item = normalizedActivities[index];
      const [result] = await connection.query(
        'INSERT INTO activities (activity, title, date, time, time_end, responsible, place, modality, file_name, file_path, file_cloudinary_id, file_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [
          item.activity,
          title,
          item.date,
          `${item.time}:00`,
          item.timeEnd ? `${item.timeEnd}:00` : null,
          item.responsible || null,
          item.place || null,
          item.modality,
          req.file.originalname,
          filePath,
          fileCloudinaryId,
          index === 0 ? fileBuffer : null,
        ]
      );
      savedActivities.push({
        id: result.insertId,
        activity: item.activity,
        date: item.date,
        time: item.time,
        time_end: item.timeEnd,
        responsible: item.responsible,
        place: item.place,
        modality: item.modality,
        file_name: req.file.originalname,
        file_path: filePath,
        file_cloudinary_id: fileCloudinaryId,
      });
    }

    await connection.commit();
    await discardUpload();
    return res.status(201).json({
      message: 'Agenda guardada correctamente',
      activities: savedActivities,
    });
  } catch (error) {
    if (connection) await connection.rollback();
    await discardUpload();
    console.error('Error al guardar agenda por lote:', error);
    return res.status(500).json({ message: 'No se pudo guardar la agenda completa' });
  } finally {
    connection?.release();
  }
});

app.post('/api/admin/activities/preview', authMiddleware, requireRole('admin'), previewUpload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Selecciona un archivo DOCX para visualizarlo' });
  }

  const validationMessage = getDocxValidationError(req.file.originalname, req.file.buffer);
  if (validationMessage) {
    return res.status(415).json({ message: validationMessage });
  }

  try {
    const result = await mammoth.convertToHtml({ buffer: req.file.buffer });
    return res.json({
      fileName: req.file.originalname,
      blocks: extractDocumentBlocks(result.value),
    });
  } catch (error) {
    console.error('Error al previsualizar documento Word:', error);
    const detail = String(error.message || '').toLowerCase();
    const message = detail.includes('end of central directory')
      ? 'El archivo DOCX llegó incompleto o está dañado. Vuelve a seleccionar el archivo original o guárdalo nuevamente desde Word.'
      : `No se pudo interpretar el DOCX: ${error.message}`;
    return res.status(422).json({
      message,
    });
  }
});

app.get('/api/admin/activities/:id/document', authMiddleware, requireRole('admin'), async (req, res) => {
  const activityId = Number(req.params.id);
  if (!Number.isInteger(activityId) || activityId < 1) {
    return res.status(400).json({ message: 'Identificador de actividad inválido' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT file_name, file_path, file_data FROM activities WHERE id = ?',
      [activityId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Actividad no encontrada' });
    }

    const fileName = rows[0].file_name || '';
    let fileBuffer = rows[0].file_data ? Buffer.from(rows[0].file_data) : null;
    if (!fileBuffer) {
      const documentPath = path.join(uploadsDir, path.basename(rows[0].file_path));
      try {
        fileBuffer = await fs.promises.readFile(documentPath);
      } catch {
        return res.status(404).json({ message: 'No se encontró el archivo Word en el servidor' });
      }
    }

    const validationMessage = getDocxValidationError(fileName, fileBuffer);
    if (validationMessage) {
      return res.status(415).json({ message: validationMessage });
    }

    if (fileBuffer) {
      const result = await mammoth.convertToHtml({ buffer: fileBuffer });
      return res.json({
        fileName,
        blocks: extractDocumentBlocks(result.value),
      });
    }

    const result = await mammoth.convertToHtml({ buffer: fileBuffer });
    return res.json({
      fileName,
      blocks: extractDocumentBlocks(result.value),
    });
  } catch (error) {
    console.error('Error al leer documento de actividad:', error);
    return res.status(422).json({ message: 'No se pudo leer el contenido del archivo Word' });
  }
});

app.put('/api/admin/activities/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const activityId = Number(req.params.id);
  const activity = typeof req.body.activity === 'string' ? req.body.activity.trim() : '';
  const date = typeof req.body.date === 'string' ? req.body.date.trim() : '';
  const time = typeof req.body.time === 'string' ? req.body.time.trim() : '';
  const modality = typeof req.body.modality === 'string' ? req.body.modality.trim() : '';
  const responsible = typeof req.body.responsible === 'string' ? req.body.responsible.trim() : '';
  const place = typeof req.body.place === 'string' ? req.body.place.trim() : '';

  if (!Number.isInteger(activityId) || activityId < 1) {
    return res.status(400).json({ message: 'Identificador de actividad inválido' });
  }

  if (!activity || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) {
    return res.status(400).json({ message: 'Fecha, hora y actividad son obligatorias y deben ser válidas' });
  }

  try {
    const [existingRows] = await pool.query('SELECT id FROM activities WHERE id = ?', [activityId]);
    if (existingRows.length === 0) {
      return res.status(404).json({ message: 'Actividad no encontrada' });
    }

    await pool.query(
      'UPDATE activities SET activity = ?, date = ?, time = ?, responsible = ?, place = ?, modality = ? WHERE id = ?',
      [activity, date, `${time}:00`, responsible || null, place || null, modality, activityId]
    );
    return res.json({ message: 'Actividad actualizada correctamente' });
  } catch (error) {
    console.error('Error al actualizar actividad:', error);
    return res.status(500).json({ message: 'No se pudo actualizar la actividad' });
  }
});

app.delete('/api/admin/activities/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const activityId = Number(req.params.id);
  if (!Number.isInteger(activityId) || activityId < 1) {
    return res.status(400).json({ message: 'Identificador de actividad inválido' });
  }

  try {
    const [activities] = await pool.query(
      'SELECT file_path, file_cloudinary_id FROM activities WHERE id = ?',
      [activityId]
    );
    if (activities.length === 0) {
      return res.status(404).json({ message: 'Actividad no encontrada' });
    }

    await pool.query('DELETE FROM activities WHERE id = ?', [activityId]);

    const filePath = activities[0].file_path;
    if (filePath) {
      const [remainingActivities] = await pool.query(
        'SELECT id FROM activities WHERE file_path = ? LIMIT 1',
        [filePath]
      );
      if (remainingActivities.length === 0) {
        await deleteCloudinaryAsset(activities[0].file_cloudinary_id, 'raw');
        if (filePath?.startsWith('/uploads/')) {
          const storedPath = path.join(uploadsDir, path.basename(filePath));
          await fs.promises.unlink(storedPath).catch(() => {});
        }
      }
    }

    return res.json({ message: 'Actividad eliminada correctamente' });
  } catch (error) {
    console.error('Error al eliminar actividad:', error);
    return res.status(500).json({ message: 'No se pudo eliminar la actividad' });
  }
});

app.post('/api/admin/activities', authMiddleware, requireRole('admin'), upload.single('file'), async (req, res) => {
  const activity = typeof req.body.activity === 'string' ? req.body.activity.trim() : '';
  const title = typeof req.body.title === 'string' ? req.body.title.trim() : activity;
  const description = typeof req.body.description === 'string' ? req.body.description.trim() : '';
  const date = typeof req.body.date === 'string' ? req.body.date.trim() : '';
  const time = typeof req.body.time === 'string' ? req.body.time.trim() : '';
  const modality = typeof req.body.modality === 'string' ? req.body.modality.trim() : '';
  const responsible = typeof req.body.responsible === 'string' ? req.body.responsible.trim() : '';
  const place = typeof req.body.place === 'string' ? req.body.place.trim() : '';
  const typeName = typeof req.body.type === 'string' ? req.body.type.trim() : 'Otro';
  const speakerName = typeof req.body.speaker_name === 'string' ? req.body.speaker_name.trim() : '';
  const speakerIds = Array.isArray(req.body.speaker_ids)
    ? req.body.speaker_ids.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0)
    : [];

  if (!title || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) {
    return res.status(400).json({ message: 'Título, fecha, hora y actividad son obligatorias y deben ser válidas' });
  }

  try {
    let typeId = null;
    const [typeRows] = await pool.query('SELECT id FROM activity_types WHERE name = ?', [typeName]);
    if (typeRows.length > 0) {
      typeId = typeRows[0].id;
    } else {
      const [insertType] = await pool.query('INSERT INTO activity_types (name) VALUES (?)', [typeName]);
      typeId = insertType.insertId;
    }

    let fileData = null;
    let uploadedDocument = null;
    if (req.file) {
      fileData = await fs.promises.readFile(req.file.path);
      const validationMessage = getDocxValidationError(req.file.originalname, fileData);
      if (validationMessage) {
        await fs.promises.unlink(req.file.path).catch(() => {});
        return res.status(415).json({ message: validationMessage });
      }
      uploadedDocument = await uploadToCloudinary(fileData, {
        folder: `${cloudinaryFolder}/activities`,
        resourceType: 'raw',
        publicId: `${Date.now()}_${path.basename(req.file.originalname)}`,
      });
      await fs.promises.unlink(req.file.path).catch(() => {});
    }

    const [result] = await pool.query(
      `INSERT INTO activities
       (activity, title, description, date, time, responsible, place, modality,
        activity_type_id, file_name, file_path, file_cloudinary_id, file_data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [activity || title, title, description, date, `${time}:00`,
        responsible || null, place || null, modality, typeId,
        req.file?.originalname ?? null, uploadedDocument?.secure_url || null,
        uploadedDocument?.public_id || null, fileData]
    );

    const finalSpeakerIds = [...speakerIds];
    if (speakerName) {
      const existingSpeaker = await pool.query('SELECT id FROM speakers WHERE name = ?', [speakerName]);
      if (existingSpeaker[0].length > 0) {
        finalSpeakerIds.push(existingSpeaker[0][0].id);
      } else {
        const insertedSpeaker = await pool.query('INSERT INTO speakers (name) VALUES (?)', [speakerName]);
        finalSpeakerIds.push(insertedSpeaker[0].insertId);
      }
    }

    if (finalSpeakerIds.length > 0) {
      const uniqueSpeakerIds = [...new Set(finalSpeakerIds)];
      const values = uniqueSpeakerIds.map((speakerId) => [result.insertId, speakerId]);
      await pool.query('INSERT INTO activity_speakers (activity_id, speaker_id) VALUES ?', [values]);
    }

    return res.status(201).json({
      message: 'Actividad guardada correctamente',
      activity: {
        id: result.insertId,
        activity: activity || title,
        title,
        description,
        date,
        time,
        responsible,
        place,
        modality,
        type: typeName,
        fileName: req.file?.originalname ?? '',
        filePath: uploadedDocument?.secure_url || '',
        speakers: finalSpeakerIds,
      },
    });
  } catch (error) {
    console.error('Error al guardar actividad:', error);
    return res.status(500).json({ message: 'No se pudo guardar la actividad' });
  }
});

const MIN_SPEAKER_CV_WORDS = 100;
const MAX_SPEAKER_PHOTO_BYTES = 5 * 1024 * 1024;

const speakerUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
}).fields([
  { name: 'photo', maxCount: 1 },
  { name: 'cv', maxCount: 1 },
]);

function handleSpeakerUpload(req, res, next) {
  speakerUpload(req, res, (error) => {
    if (error) {
      const message = error.code === 'LIMIT_FILE_SIZE'
        ? 'Los archivos no pueden superar 10 MB'
        : 'No se pudieron recibir los archivos del conferencista';
      return res.status(400).json({ message });
    }
    next();
  });
}

function detectImageExtension(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return '.jpg';
  const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buffer.subarray(0, 8).equals(pngSignature)) return '.png';
  if (buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') {
    return '.webp';
  }
  return null;
}

async function countCvWords(fileName, buffer) {
  const text = (await mammoth.extractRawText({ buffer })).value;
  return text.split(/\s+/).filter((word) => /[\p{L}\p{N}]/u.test(word)).length;
}

async function prepareSpeakerFiles(req) {
  const result = { photo: null, cv: null };
  const photoFile = req.files?.photo?.[0];
  const cvFile = req.files?.cv?.[0];

  if (photoFile) {
    const extension = detectImageExtension(photoFile.buffer);
    if (!extension) {
      return { error: 'La foto debe ser una imagen JPG, PNG o WEBP válida' };
    }
    if (photoFile.size > MAX_SPEAKER_PHOTO_BYTES) {
      return { error: 'La foto no puede superar 5 MB' };
    }
    result.photo = { buffer: photoFile.buffer, extension };
  }

  if (cvFile) {
    const extension = path.extname(String(cvFile.originalname || '')).toLowerCase();
    let validationMessage;
    if (extension === '.docx') {
      validationMessage = getDocxValidationError(cvFile.originalname, cvFile.buffer);
    } else {
      validationMessage = 'La hoja de vida debe ser un archivo Word (.docx) válido.';
    }
    if (validationMessage) return { error: validationMessage };

    let wordCount;
    try {
      wordCount = await countCvWords(cvFile.originalname, cvFile.buffer);
    } catch (error) {
      console.error('Error al leer la hoja de vida:', error);
      return { error: 'No se pudo leer el contenido de la hoja de vida' };
    }
    if (wordCount < MIN_SPEAKER_CV_WORDS) {
      return {
        error: `La hoja de vida tiene ${wordCount} palabras. El mínimo es ${MIN_SPEAKER_CV_WORDS}.`,
      };
    }
    result.cv = {
      buffer: cvFile.buffer,
      extension,
      fileName: path.basename(cvFile.originalname).slice(0, 255),
      wordCount,
    };
  }

  return result;
}

async function storeSpeakerFile(prefix, extension, buffer) {
  const result = await uploadToCloudinary(buffer, {
    folder: `${cloudinaryFolder}/speakers`,
    resourceType: prefix === 'speaker_photo' ? 'image' : 'raw',
    type: prefix === 'speaker_photo' ? 'upload' : 'authenticated',
    publicId: `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${extension}`,
  });
  return {
    url: prefix === 'speaker_cv'
      ? cloudinaryRawUrl(result.public_id)
      : result.secure_url,
    publicId: result.public_id,
  };
}

async function removeStoredFile(storedPath) {
  if (!storedPath) return;
  await fs.promises.unlink(path.join(uploadsDir, path.basename(storedPath))).catch(() => {});
}

function serializeSpeaker(row) {
  return {
    id: row.id,
    name: row.name,
    photoPath: row.photo_path || '',
    cvFileName: row.cv_file_name || '',
    cvFilePath: cloudinaryRawUrl(row.cv_cloudinary_id) || row.cv_file_path || '',
    cvWordCount: Number(row.cv_word_count) || 0,
    activityCount: Number(row.activity_count) || 0,
  };
}

async function sendSpeakers(_req, res) {
  try {
    const [rows] = await pool.query(`
      SELECT s.id, s.name, s.photo_path, s.cv_file_name, s.cv_file_path,
             s.cv_cloudinary_id, s.cv_word_count,
             COUNT(aps.activity_id) AS activity_count
      FROM speakers s
      LEFT JOIN activity_speakers aps ON aps.speaker_id = s.id
      GROUP BY s.id, s.name, s.photo_path, s.cv_file_name, s.cv_file_path,
               s.cv_cloudinary_id, s.cv_word_count
      ORDER BY s.name ASC
    `);
    return res.json({
      minCvWords: MIN_SPEAKER_CV_WORDS,
      speakers: rows.map(serializeSpeaker),
    });
  } catch (error) {
    console.error('Error al consultar conferencistas:', error);
    return res.status(500).json({ message: 'No se pudo cargar la lista de conferencistas' });
  }
}

app.get('/api/speakers', authMiddleware, sendSpeakers);

app.post('/api/admin/speakers', authMiddleware, requireRole('admin'), handleSpeakerUpload, async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim().replace(/\s+/g, ' ') : '';
  if (name.length < 3 || name.length > 150) {
    return res.status(400).json({ message: 'El nombre debe tener entre 3 y 150 caracteres' });
  }
  if (!req.files?.photo?.[0] || !req.files?.cv?.[0]) {
    return res.status(400).json({
      message: 'La foto y la hoja de vida Word (.docx) son obligatorias',
    });
  }

  const files = await prepareSpeakerFiles(req);
  if (files.error) return res.status(422).json({ message: files.error });

  let photoPath;
  let cvPath;
  try {
    const [duplicates] = await pool.query(
      'SELECT id FROM speakers WHERE LOWER(name) = LOWER(?) LIMIT 1',
      [name]
    );
    if (duplicates.length > 0) {
      return res.status(409).json({ message: 'Ya existe un conferencista con ese nombre' });
    }

    photoPath = await storeSpeakerFile('speaker_photo', files.photo.extension, files.photo.buffer);
    cvPath = await storeSpeakerFile('speaker_cv', files.cv.extension, files.cv.buffer);
    const [result] = await pool.query(
      `INSERT INTO speakers
       (name, photo_path, photo_cloudinary_id, cv_file_name, cv_file_path,
        cv_cloudinary_id, cv_word_count)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, photoPath.url, photoPath.publicId, files.cv.fileName, cvPath.url,
        cvPath.publicId, files.cv.wordCount]
    );
    return res.status(201).json({
      message: 'Conferencista guardado correctamente',
      id: result.insertId,
    });
  } catch (error) {
    await deleteCloudinaryAsset(photoPath?.publicId, 'image');
    await deleteCloudinaryAsset(cvPath?.publicId, 'raw');
    console.error('Error al guardar conferencista:', error);
    return res.status(500).json({ message: 'No se pudo guardar el conferencista' });
  }
});

app.put('/api/admin/speakers/:id', authMiddleware, requireRole('admin'), handleSpeakerUpload, async (req, res) => {
  const speakerId = Number(req.params.id);
  if (!Number.isInteger(speakerId) || speakerId < 1) {
    return res.status(400).json({ message: 'Identificador de conferencista inválido' });
  }

  const files = await prepareSpeakerFiles(req);
  if (files.error) return res.status(422).json({ message: files.error });

  let newPhotoPath;
  let newCvPath;
  try {
    const [rows] = await pool.query('SELECT * FROM speakers WHERE id = ?', [speakerId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Conferencista no encontrado' });
    }
    const current = rows[0];

    const name = typeof req.body.name === 'string' && req.body.name.trim()
      ? req.body.name.trim().replace(/\s+/g, ' ')
      : current.name;
    if (name.length < 3 || name.length > 150) {
      return res.status(400).json({ message: 'El nombre debe tener entre 3 y 150 caracteres' });
    }

    const [duplicates] = await pool.query(
      'SELECT id FROM speakers WHERE LOWER(name) = LOWER(?) AND id <> ? LIMIT 1',
      [name, speakerId]
    );
    if (duplicates.length > 0) {
      return res.status(409).json({ message: 'Ya existe un conferencista con ese nombre' });
    }

    if (files.photo) {
      newPhotoPath = await storeSpeakerFile('speaker_photo', files.photo.extension, files.photo.buffer);
    }
    if (files.cv) {
      newCvPath = await storeSpeakerFile('speaker_cv', files.cv.extension, files.cv.buffer);
    }

    await pool.query(
      `UPDATE speakers
       SET name = ?, photo_path = ?, photo_cloudinary_id = ?, cv_file_name = ?,
           cv_file_path = ?, cv_cloudinary_id = ?, cv_word_count = ?
       WHERE id = ?`,
      [
        name,
        newPhotoPath?.url ?? current.photo_path,
        newPhotoPath?.publicId ?? current.photo_cloudinary_id,
        files.cv ? files.cv.fileName : current.cv_file_name,
        newCvPath?.url ?? current.cv_file_path,
        newCvPath?.publicId ?? current.cv_cloudinary_id,
        files.cv ? files.cv.wordCount : current.cv_word_count,
        speakerId,
      ]
    );

    if (newPhotoPath) {
      await deleteCloudinaryAsset(current.photo_cloudinary_id, 'image');
      await removeStoredFile(current.photo_path);
    }
    if (newCvPath) {
      await deleteCloudinaryAsset(current.cv_cloudinary_id, 'raw');
      await removeStoredFile(current.cv_file_path);
    }
    return res.json({ message: 'Conferencista actualizado correctamente' });
  } catch (error) {
    await deleteCloudinaryAsset(newPhotoPath?.publicId, 'image');
    await deleteCloudinaryAsset(newCvPath?.publicId, 'raw');
    console.error('Error al actualizar conferencista:', error);
    return res.status(500).json({ message: 'No se pudo actualizar el conferencista' });
  }
});

app.delete('/api/admin/speakers/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const speakerId = Number(req.params.id);
  if (!Number.isInteger(speakerId) || speakerId < 1) {
    return res.status(400).json({ message: 'Identificador de conferencista inválido' });
  }

  try {
    const [rows] = await pool.query(
      `SELECT photo_path, cv_file_path, photo_cloudinary_id,
              cv_cloudinary_id FROM speakers WHERE id = ?`,
      [speakerId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Conferencista no encontrado' });
    }

    await pool.query('DELETE FROM speakers WHERE id = ?', [speakerId]);
    await removeStoredFile(rows[0].photo_path);
    await removeStoredFile(rows[0].cv_file_path);
    await deleteCloudinaryAsset(rows[0].photo_cloudinary_id, 'image');
    await deleteCloudinaryAsset(rows[0].cv_cloudinary_id, 'raw');
    return res.json({ message: 'Conferencista eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar conferencista:', error);
    return res.status(500).json({ message: 'No se pudo eliminar el conferencista' });
  }
});

function requireAnyRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'No tienes permisos para acceder a este recurso' });
    }
    next();
  };
}

const attendanceKinds = new Set(['attendance', 'break']);

// El QR de asistencia es dinámico: caduca en segundos y solo sirve una vez,
// por lo que una foto o captura del QR no puede usarse para registrarse.
const QR_TTL_SECONDS = 20;
const usedQrSignatures = new Map();

function qrSignature(userId, expires, nonce) {
  return crypto
    .createHmac('sha256', `qr:${process.env.JWT_SECRET || 'secret_key'}`)
    .update(`${userId}|${expires}|${nonce}`)
    .digest('hex')
    .slice(0, 32);
}

function buildLiveQr(userId) {
  const expires = Math.floor(Date.now() / 1000) + QR_TTL_SECONDS;
  const nonce = crypto.randomBytes(6).toString('hex');
  return `UNESUM|LIVE|${userId}|${expires}|${nonce}|${qrSignature(userId, expires, nonce)}`;
}

function parseUserQr(code) {
  const parts = String(code || '').trim().split('|');
  if (parts.length !== 6 || parts[0] !== 'UNESUM' || parts[1] !== 'LIVE') {
    return null;
  }
  const userId = Number(parts[2]);
  const expires = Number(parts[3]);
  const [nonce, signature] = [parts[4], parts[5]];
  if (!Number.isInteger(userId) || userId < 1 || !Number.isInteger(expires)) {
    return null;
  }
  const expected = Buffer.from(qrSignature(userId, expires, nonce));
  const received = Buffer.from(signature);
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return null;
  }
  return { userId, expires, signature };
}

function consumeQr(parsed) {
  const now = Math.floor(Date.now() / 1000);
  for (const [key, expires] of usedQrSignatures) {
    if (expires < now) usedQrSignatures.delete(key);
  }
  if (parsed.expires < now) return 'expired';
  if (usedQrSignatures.has(parsed.signature)) return 'used';
  usedQrSignatures.set(parsed.signature, parsed.expires);
  return 'ok';
}

app.get('/api/my/qr', authMiddleware, (req, res) => {
  res.json({ code: buildLiveQr(req.user.id), expiresIn: QR_TTL_SECONDS });
});

async function recordAttendance({ userId, email, kind, date, recordedBy }) {
  const [users] = await pool.query(
    'SELECT id, name, email, role FROM users WHERE id = ?',
    [userId]
  );
  if (users.length === 0 || users[0].role !== 'teacher' ||
      (email && users[0].email.toLowerCase() !== email)) {
    return { status: 'invalid' };
  }
  const user = users[0];
  const [result] = await pool.query(
    `INSERT IGNORE INTO attendance_records
     (user_id, kind, event_date, recorded_by, created_at)
     VALUES (?, ?, COALESCE(?, CURDATE()), ?,
             COALESCE(TIMESTAMP(?, CURRENT_TIME()), CURRENT_TIMESTAMP()))`,
    [user.id, kind, date ?? null, recordedBy, date ?? null]
  );
  return {
    status: result.affectedRows === 1 ? 'registered' : 'duplicate',
    user: { id: user.id, name: user.name, email: user.email },
  };
}

async function hasAttendanceRecord(userId, kind) {
  const [rows] = await pool.query(
    `SELECT 1
     FROM attendance_records
     WHERE user_id = ? AND kind = ? AND event_date = CURDATE()
     LIMIT 1`,
    [userId, kind]
  );
  return rows.length > 0;
}

app.post('/api/attendance/scan', authMiddleware, requireAnyRole('attendant', 'admin'), async (req, res) => {
  const kind = req.body.kind;
  const parsed = parseUserQr(req.body.code);
  if (!attendanceKinds.has(kind)) {
    return res.status(400).json({ message: 'Tipo de registro inválido' });
  }
  if (!parsed) {
    return res.status(422).json({
      message: 'No está permitido escanear fotos ni capturas. El docente debe mostrar el QR actual desde su aplicación.',
    });
  }

  try {
    if (await hasAttendanceRecord(parsed.userId, kind)) {
      const [users] = await pool.query(
        'SELECT id, name, email FROM users WHERE id = ? AND role = ?',
        [parsed.userId, 'teacher']
      );
      const user = users[0];
      if (user) {
        return res.json({
          status: 'duplicate',
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
          },
        });
      }
    }
  } catch (error) {
    console.error('Error al comprobar el registro existente:', error);
    return res.status(500).json({ message: 'No se pudo comprobar el registro existente' });
  }

  try {
    const scheduleStatus = await getAttendanceScheduleStatus(kind);
    if (!scheduleStatus.configured) {
      return res.status(403).json({
        message: 'El administrador todavía no ha configurado el horario de este día.',
      });
    }
    if (!scheduleStatus.open) {
      const schedule = scheduleStatus.schedule;
      const start = kind === 'attendance' ? schedule.attendance_start : schedule.break_start;
      const end = kind === 'attendance' ? schedule.attendance_end : schedule.break_end;
      return res.status(403).json({
        message: `El horario de ${kind === 'attendance' ? 'asistencia' : 'coffee break'} es de ${start} a ${end}. El escaneo no está habilitado en este momento.`,
      });
    }
  } catch (error) {
    console.error('Error al validar el horario de asistencia:', error);
    return res.status(500).json({ message: 'No se pudo validar el horario de registro' });
  }
  const qrState = consumeQr(parsed);
  if (qrState !== 'ok') {
    return res.status(422).json({
      message: 'El QR caducó o ya fue usado. Pide al docente que muestre el QR actual en su celular.',
    });
  }
  try {
    const result = await recordAttendance({ ...parsed, kind, recordedBy: req.user.id });
    if (result.status === 'invalid') {
      return res.status(404).json({ message: 'El docente del código QR no existe' });
    }
    return res.json(result);
  } catch (error) {
    console.error('Error al registrar asistencia:', error);
    return res.status(500).json({ message: 'No se pudo registrar la asistencia' });
  }
});

app.delete('/api/attendance', authMiddleware, requireRole('admin'), async (req, res) => {
  const userId = Number(req.body.userId);
  const kind = req.body.kind;
  const date = typeof req.body.date === 'string' ? req.body.date : '';
  if (!Number.isInteger(userId) || userId < 1 || !attendanceKinds.has(kind) ||
      !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ message: 'Datos de registro inválidos' });
  }
  try {
    const [result] = await pool.query(
      'DELETE FROM attendance_records WHERE user_id = ? AND kind = ? AND event_date = ?',
      [userId, kind, date]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'No existe ese registro' });
    }
    return res.json({ message: 'Registro eliminado' });
  } catch (error) {
    console.error('Error al quitar asistencia:', error);
    return res.status(500).json({ message: 'No se pudo quitar el registro' });
  }
});

app.post('/api/admin/attendance', authMiddleware, requireRole('admin'), async (req, res) => {
  const userId = Number(req.body.userId);
  const kind = req.body.kind;
  const date = typeof req.body.date === 'string' ? req.body.date : '';
  if (!Number.isInteger(userId) || userId < 1 || !attendanceKinds.has(kind) ||
      !isValidCalendarDate(date)) {
    return res.status(400).json({ message: 'Datos de registro inválidos' });
  }

  try {
    const result = await recordAttendance({
      userId,
      kind,
      date,
      recordedBy: req.user.id,
    });
    if (result.status === 'invalid') {
      return res.status(404).json({ message: 'No se encontró el docente' });
    }
    return res.json({
      status: result.status,
      message: result.status === 'registered'
        ? 'Registro agregado correctamente'
        : 'El docente ya tiene este registro',
    });
  } catch (error) {
    console.error('Error al agregar registro de asistencia:', error);
    return res.status(500).json({ message: 'No se pudo agregar el registro' });
  }
});

app.delete('/api/admin/attendance/day', authMiddleware, requireRole('admin'), async (req, res) => {
  const date = typeof req.body.date === 'string' ? req.body.date : '';
  if (!isValidCalendarDate(date)) {
    return res.status(400).json({ message: 'La fecha no es válida' });
  }

  let connection;
  let filePaths = [];
  let attendanceCount = 0;
  let activityCount = 0;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [activities] = await connection.query(
      'SELECT file_path FROM activities WHERE date = ?',
      [date]
    );
    const [attendanceResult] = await connection.query(
      'DELETE FROM attendance_records WHERE event_date = ?',
      [date]
    );
    const [scheduleResult] = await connection.query(
      'DELETE FROM attendance_schedules WHERE event_date = ?',
      [date]
    );
    const [windowResult] = await connection.query(
      'DELETE FROM attendance_schedule_windows WHERE event_date = ?',
      [date]
    );
    const [activityResult] = await connection.query(
      'DELETE FROM activities WHERE date = ?',
      [date]
    );
    attendanceCount = attendanceResult.affectedRows;
    activityCount = activityResult.affectedRows;
    if (attendanceCount === 0 && activityCount === 0 &&
        scheduleResult.affectedRows === 0 && windowResult.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ message: 'No hay datos para quitar en ese día' });
    }
    await connection.commit();
    filePaths = [...new Set(activities.map((activity) => activity.file_path).filter(Boolean))];
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error al quitar el día del seminario:', error);
    return res.status(500).json({ message: 'No se pudo quitar el día' });
  } finally {
    connection?.release();
  }

  try {
    for (const filePath of filePaths) {
      const [remainingActivities] = await pool.query(
        'SELECT id FROM activities WHERE file_path = ? LIMIT 1',
        [filePath]
      );
      if (remainingActivities.length === 0) {
        await fs.promises.unlink(path.join(uploadsDir, path.basename(filePath))).catch(() => {});
      }
    }
  } catch (error) {
    console.error('No se pudieron limpiar archivos de actividades eliminadas:', error);
  }

  return res.json({
    message: 'Día eliminado correctamente',
    attendanceCount,
    activityCount,
  });
});

app.get('/api/admin/attendance/schedule', authMiddleware, requireRole('admin'), async (req, res) => {
    const date = typeof req.query.date === 'string' ? req.query.date : '';
    if (!isValidCalendarDate(date)) {
      return res.status(400).json({ message: 'La fecha no es válida' });
    }
    try {
      const [rows] = await pool.query(
        `SELECT id,
                DATE_FORMAT(attendance_start, '%H:%i') AS attendanceStart,
                DATE_FORMAT(attendance_end, '%H:%i') AS attendanceEnd,
                DATE_FORMAT(break_start, '%H:%i') AS breakStart,
                DATE_FORMAT(break_end, '%H:%i') AS breakEnd,
                attendance_enabled AS attendanceEnabled,
                break_enabled AS breakEnabled
         FROM attendance_schedule_windows WHERE event_date = ? ORDER BY id`,
        [date]
      );
      return res.json({ date, schedule: rows[0] || null });
    } catch (error) {
      console.error('Error al consultar el horario de asistencia:', error);
      return res.status(500).json({ message: 'No se pudo consultar el horario' });
    }
  });

app.put('/api/admin/attendance/schedule', authMiddleware, requireRole('admin'), async (req, res) => {
    const date = typeof req.body.date === 'string' ? req.body.date : '';
    const schedules = req.body.schedules;
    if (!isValidCalendarDate(date) || !Array.isArray(schedules) ||
        schedules.length < 1 || schedules.length > 20 ||
        schedules.some((item) =>
          (item?.attendanceEnabled !== false &&
            (!TIME_PATTERN.test(item?.attendanceStart || '') ||
              !TIME_PATTERN.test(item?.attendanceEnd || '') ||
              item.attendanceStart >= item.attendanceEnd)) ||
          (item?.breakEnabled !== false &&
            (!TIME_PATTERN.test(item?.breakStart || '') ||
              !TIME_PATTERN.test(item?.breakEnd || '') ||
              item.breakStart >= item.breakEnd)) ||
          (item?.attendanceEnabled === false && item?.breakEnabled === false))) {
      return res.status(400).json({
        message: 'Cada hora debe tener formato HH:mm y la hora inicial debe ser menor que la final.',
      });
    }
    try {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        await connection.query('DELETE FROM attendance_schedule_windows WHERE event_date = ?', [date]);
        for (const item of schedules) {
          await connection.query(
            `INSERT INTO attendance_schedule_windows
             (event_date, attendance_start, attendance_end, break_start, break_end,
              attendance_enabled, break_enabled)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
              date,
              item.attendanceStart || '00:00',
              item.attendanceEnd || '00:00',
              item.breakStart || '00:00',
              item.breakEnd || '00:00',
              item.attendanceEnabled === false ? 0 : 1,
              item.breakEnabled === false ? 0 : 1,
            ]
          );
        }
        await connection.commit();
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
      return res.json({ message: 'Horario guardado correctamente' });
    } catch (error) {
      console.error('Error al guardar el horario de asistencia:', error);
      return res.status(500).json({ message: 'No se pudo guardar el horario' });
    }
});

async function sendAttendanceDay(req, res, includeAllTeachers) {
  try {
    const [todayRows] = await pool.query("SELECT DATE_FORMAT(CURDATE(), '%Y-%m-%d') AS today");
    const today = todayRows[0].today;
    const requested = typeof req.query.date === 'string' ? req.query.date : '';
    if (requested && !isValidCalendarDate(requested)) {
      return res.status(400).json({ message: 'La fecha no es válida' });
    }
    const date = requested || today;
    const currentDateUnion = includeAllTeachers ? '' : 'UNION SELECT CURDATE()';

    const [dayRows] = await pool.query(
      `SELECT DATE_FORMAT(d, '%Y-%m-%d') AS day FROM (
         SELECT date AS d FROM activities
         UNION SELECT event_date FROM attendance_records
           UNION SELECT event_date FROM attendance_schedule_windows
           ${currentDateUnion}
       ) days ORDER BY d`
    );
    const [rows] = await pool.query(
      `SELECT u.id, u.name, u.email,
              MAX(CASE WHEN a.kind = 'attendance' THEN DATE_FORMAT(a.created_at, '%H:%i') END) AS attendance_time,
              MAX(CASE WHEN a.kind = 'break' THEN DATE_FORMAT(a.created_at, '%H:%i') END) AS break_time
       FROM users u
       LEFT JOIN attendance_records a ON a.user_id = u.id AND a.event_date = ?
       WHERE u.role = 'teacher' AND (? = 1 OR a.id IS NOT NULL)
       GROUP BY u.id, u.name, u.email
       ORDER BY u.name`,
      [date, includeAllTeachers ? 1 : 0]
    );
    const [[totals]] = await pool.query("SELECT COUNT(*) AS total FROM users WHERE role = 'teacher'");
    const [scheduleRows] = await pool.query(
      `SELECT DATE_FORMAT(attendance_start, '%H:%i') AS attendanceStart,
              DATE_FORMAT(attendance_end, '%H:%i') AS attendanceEnd,
              DATE_FORMAT(break_start, '%H:%i') AS breakStart,
              DATE_FORMAT(break_end, '%H:%i') AS breakEnd,
              attendance_enabled AS attendanceEnabled,
              break_enabled AS breakEnabled
       FROM attendance_schedule_windows WHERE event_date = ? ORDER BY id`,
      [date]
    );
    return res.json({
      date,
      today,
      days: dayRows.map((row) => row.day),
      totalTeachers: totals.total,
      schedules: scheduleRows,
      teachers: rows.map((row) => ({
        id: row.id,
        name: row.name,
        email: row.email,
        attendanceTime: row.attendance_time,
        breakTime: row.break_time,
      })),
    });
  } catch (error) {
    console.error('Error al consultar asistencia:', error);
    return res.status(500).json({ message: 'No se pudo consultar la asistencia' });
  }
}

app.get('/api/attendance/day', authMiddleware, requireAnyRole('attendant', 'admin'), (req, res) =>
  sendAttendanceDay(req, res, false));

app.get('/api/admin/attendance/day', authMiddleware, requireRole('admin'), (req, res) =>
  sendAttendanceDay(req, res, true));

app.use((error, _req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        message: `El archivo supera el tamaño máximo permitido de ${sectionMaxFileSizeMb} MB.`,
      });
    }
    return res.status(400).json({ message: `Error al subir el archivo: ${error.message}` });
  }
  if (error?.message?.startsWith('Solo se permiten')) {
    return res.status(400).json({ message: error.message });
  }
  if (error) {
    console.error('Error no controlado en el servidor:', error);
    return res.status(500).json({ message: 'No se pudo procesar la solicitud.' });
  }
  next();
});

async function startServer() {
  try {
    await initDatabase();
    console.log(
      `Proveedor de correo: ${
        mailProvider === 'resend' || resendApiKey
          ? 'Resend API'
          : mailProvider === 'gmail_api'
            ? 'Gmail API'
            : mailProvider === 'gmail' || mailProvider === 'gmail_oauth2'
              ? 'Gmail OAuth2'
            : mailTransporter
              ? 'SMTP'
              : 'no configurado'
      }`,
    );
    app.listen(port, '0.0.0.0', () => {
      console.log(`Servidor corriendo en el puerto ${port}`);
    });
  } catch (error) {
    console.error('No se pudo iniciar la base de datos:', error.message);
    process.exit(1);
  }
}

startServer();
