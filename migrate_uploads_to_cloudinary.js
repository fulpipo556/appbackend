require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const { v2: cloudinary } = require('cloudinary');

const uploadsDir = path.join(__dirname, 'uploads');
const cloudinaryFolder = process.env.CLOUDINARY_FOLDER || 'fotosyhojas';

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

function requireConfiguration() {
  const missing = [
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET',
  ].filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Faltan variables de Cloudinary: ${missing.join(', ')}`);
  }
}

function upload(buffer, options) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      options,
      (error, result) => (error ? reject(error) : resolve(result)),
    );
    stream.end(buffer);
  });
}

function localPath(storedPath) {
  if (!storedPath || !storedPath.startsWith('/uploads/')) return null;
  return path.join(uploadsDir, path.basename(storedPath));
}

async function readStoredFile(storedPath, fallbackBuffer = null) {
  const filePath = localPath(storedPath);
  if (filePath) {
    try {
      return await fs.promises.readFile(filePath);
    } catch {
      // Use the database copy for activities when the local file is missing.
    }
  }
  if (fallbackBuffer) return Buffer.from(fallbackBuffer);
  throw new Error(`No se encontró el archivo local: ${storedPath}`);
}

async function ensureCloudinaryColumns(pool) {
  const columns = [
    ['content_sections', 'image_cloudinary_id'],
    ['content_sections', 'video_cloudinary_id'],
    ['speakers', 'photo_cloudinary_id'],
    ['speakers', 'cv_cloudinary_id'],
    ['activities', 'file_cloudinary_id'],
  ];
  for (const [table, column] of columns) {
    const [existing] = await pool.query(
      `SHOW COLUMNS FROM ${table} LIKE ?`,
      [column],
    );
    if (existing.length === 0) {
      await pool.query(
        `ALTER TABLE ${table} ADD COLUMN ${column} VARCHAR(255) NULL`,
      );
    }
  }
}

async function migrateSections(pool, cache) {
  const [rows] = await pool.query(
    `SELECT id, image_path, video_path, image_cloudinary_id,
            video_cloudinary_id
     FROM content_sections`,
  );
  for (const row of rows) {
    const update = {};
    if (row.image_path?.startsWith('/uploads/') && !row.image_cloudinary_id) {
      const key = `image:${row.image_path}`;
      const result = cache[key] || await upload(
        await readStoredFile(row.image_path),
        { folder: `${cloudinaryFolder}/sections`, resource_type: 'image' },
      );
      cache[key] = result;
      update.image_path = result.secure_url;
      update.image_cloudinary_id = result.public_id;
    }
    if (row.video_path?.startsWith('/uploads/') && !row.video_cloudinary_id) {
      const key = `video:${row.video_path}`;
      const result = cache[key] || await upload(
        await readStoredFile(row.video_path),
        { folder: `${cloudinaryFolder}/sections`, resource_type: 'video' },
      );
      cache[key] = result;
      update.video_path = result.secure_url;
      update.video_cloudinary_id = result.public_id;
    }
    if (update.image_path || update.video_path) {
      await pool.query(
        `UPDATE content_sections
         SET image_path = COALESCE(?, image_path),
             image_cloudinary_id = COALESCE(?, image_cloudinary_id),
             video_path = COALESCE(?, video_path),
             video_cloudinary_id = COALESCE(?, video_cloudinary_id)
         WHERE id = ?`,
        [
          update.image_path || null,
          update.image_cloudinary_id || null,
          update.video_path || null,
          update.video_cloudinary_id || null,
          row.id,
        ],
      );
    }
  }
  return rows.length;
}

async function migrateSpeakers(pool, cache) {
  const [rows] = await pool.query(
    `SELECT id, photo_path, photo_cloudinary_id,
            cv_file_path, cv_cloudinary_id
     FROM speakers`,
  );
  for (const row of rows) {
    const update = {};
    if (row.photo_path?.startsWith('/uploads/') && !row.photo_cloudinary_id) {
      const key = `speaker-image:${row.photo_path}`;
      const result = cache[key] || await upload(
        await readStoredFile(row.photo_path),
        { folder: `${cloudinaryFolder}/speakers`, resource_type: 'image' },
      );
      cache[key] = result;
      update.photo_path = result.secure_url;
      update.photo_cloudinary_id = result.public_id;
    }
    if (row.cv_file_path?.startsWith('/uploads/') && !row.cv_cloudinary_id) {
      const key = `speaker-cv:${row.cv_file_path}`;
      const result = cache[key] || await upload(
        await readStoredFile(row.cv_file_path),
        {
          folder: `${cloudinaryFolder}/speakers`,
          resource_type: 'raw',
          public_id: path.basename(row.cv_file_path),
        },
      );
      cache[key] = result;
      update.cv_file_path = result.secure_url;
      update.cv_cloudinary_id = result.public_id;
    }
    if (update.photo_path || update.cv_file_path) {
      await pool.query(
        `UPDATE speakers
         SET photo_path = COALESCE(?, photo_path),
             photo_cloudinary_id = COALESCE(?, photo_cloudinary_id),
             cv_file_path = COALESCE(?, cv_file_path),
             cv_cloudinary_id = COALESCE(?, cv_cloudinary_id)
         WHERE id = ?`,
        [
          update.photo_path || null,
          update.photo_cloudinary_id || null,
          update.cv_file_path || null,
          update.cv_cloudinary_id || null,
          row.id,
        ],
      );
    }
  }
  return rows.length;
}

async function migrateActivities(pool, cache) {
  const [rows] = await pool.query(
    `SELECT id, file_path, file_data, file_cloudinary_id
     FROM activities
     WHERE file_path IS NOT NULL AND file_cloudinary_id IS NULL`,
  );
  for (const row of rows) {
    if (!row.file_path.startsWith('/uploads/')) continue;
    const key = `activity:${row.file_path}`;
    const result = cache[key] || await upload(
      await readStoredFile(row.file_path, row.file_data),
      {
        folder: `${cloudinaryFolder}/activities`,
        resource_type: 'raw',
        public_id: path.basename(row.file_path),
      },
    );
    cache[key] = result;
    await pool.query(
      `UPDATE activities
       SET file_path = ?, file_cloudinary_id = ?
       WHERE file_path = ?`,
      [result.secure_url, result.public_id, row.file_path],
    );
  }
  return rows.length;
}

async function main() {
  requireConfiguration();
  const pool = await mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME,
  });
  const cache = {};
  try {
    await ensureCloudinaryColumns(pool);
    const sections = await migrateSections(pool, cache);
    const speakers = await migrateSpeakers(pool, cache);
    const activities = await migrateActivities(pool, cache);
    console.log(
      `Migración completada: ${sections} secciones, ` +
      `${speakers} conferencistas y ${activities} documentos de actividades.`,
    );
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error(`Migración fallida: ${error.message}`);
  process.exitCode = 1;
});
