require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");

const app = express();

const PORT = process.env.PORT || 3000;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {

    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Nur JPG, PNG oder WEBP erlaubt."));
    }

    cb(null, true);
  }
});


/* =========================================
   CORS
========================================= */

const allowedOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {

      // Erlaubt Server-zu-Server / direkte Requests
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS nicht erlaubt"));
    }
  })
);

app.use(express.json());


/* =========================================
   DATENBANK
========================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});


async function initDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS news (
      id SERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      text TEXT NOT NULL,
      image_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("News-Datenbank bereit.");

}


/* =========================================
   HILFSFUNKTION PASSWORT
========================================= */

function secureCompare(value1, value2) {

  const hash1 = crypto
    .createHash("sha256")
    .update(String(value1))
    .digest();

  const hash2 = crypto
    .createHash("sha256")
    .update(String(value2))
    .digest();

  return crypto.timingSafeEqual(hash1, hash2);

}


/* =========================================
   JWT SCHUTZ
========================================= */

function requireAuth(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {

    return res.status(401).json({
      error: "Nicht angemeldet."
    });

  }

  const token = authHeader.split(" ")[1];

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      error: "Sitzung ungültig oder abgelaufen."
    });

  }

}


/* =========================================
   STARTSEITE / TEST
========================================= */

app.get("/", (req, res) => {

  res.json({
    status: "online",
    service: "Fenerbahçe Marl Backend"
  });

});


/* =========================================
   VORSTAND LOGIN
========================================= */

app.post("/api/login", (req, res) => {

  const {
    username,
    password
  } = req.body;


  if (!username || !password) {

    return res.status(400).json({
      error: "Benutzername und Passwort erforderlich."
    });

  }


  const usernameCorrect = secureCompare(
    username,
    process.env.ADMIN_USERNAME || ""
  );

  const passwordCorrect = secureCompare(
    password,
    process.env.ADMIN_PASSWORD || ""
  );


  if (!usernameCorrect || !passwordCorrect) {

    return res.status(401).json({
      error: "Benutzername oder Passwort falsch."
    });

  }


  const token = jwt.sign(
    {
      role: "vorstand",
      username: username
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "8h"
    }
  );


  res.json({
    success: true,
    token: token
  });

});


/* =========================================
   LOGIN PRÜFEN
========================================= */

app.get("/api/auth/check", requireAuth, (req, res) => {

  res.json({
    authenticated: true,
    user: req.user.username
  });

});

/* =========================================
   BILD HOCHLADEN
   Nur Vorstand
========================================= */

app.post(
  "/api/upload",
  requireAuth,
  upload.single("image"),
  async (req, res) => {

    try {

      if (!req.file) {
        return res.status(400).json({
          error: "Kein Bild ausgewählt."
        });
      }

      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: "fenerbahce-marl/news",
          resource_type: "image"
        },
        (error, result) => {

          if (error) {

            console.error(error);

            return res.status(500).json({
              error: "Bild konnte nicht hochgeladen werden."
            });

          }

          res.json({
            success: true,
            image_url: result.secure_url,
            public_id: result.public_id
          });

        }
      );

      uploadStream.end(req.file.buffer);

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Bild konnte nicht hochgeladen werden."
      });

    }

  }
);


/* =========================================
   ALLE NEWS
   Öffentlich
========================================= */

app.get("/api/news", async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT
        id,
        title,
        text,
        image_url,
        created_at,
        updated_at
      FROM news
      ORDER BY created_at DESC
    `);


    res.json(result.rows);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "News konnten nicht geladen werden."
    });

  }

});


/* =========================================
   EINE NEWS
   Öffentlich
========================================= */

app.get("/api/news/:id", async (req, res) => {

  try {

    const result = await pool.query(
      `
      SELECT
        id,
        title,
        text,
        image_url,
        created_at,
        updated_at
      FROM news
      WHERE id = $1
      `,
      [req.params.id]
    );


    if (result.rows.length === 0) {

      return res.status(404).json({
        error: "News nicht gefunden."
      });

    }


    res.json(result.rows[0]);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "News konnte nicht geladen werden."
    });

  }

});


/* =========================================
   NEWS ERSTELLEN
   Nur Vorstand
========================================= */

app.post("/api/news", requireAuth, async (req, res) => {

  try {

    const {
      title,
      text,
      image_url
    } = req.body;


    if (!title || !text) {

      return res.status(400).json({
        error: "Überschrift und Text sind erforderlich."
      });

    }


    const result = await pool.query(
      `
      INSERT INTO news (
        title,
        text,
        image_url
      )
      VALUES ($1, $2, $3)
      RETURNING *
      `,
      [
        title.trim(),
        text.trim(),
        image_url || null
      ]
    );


    res.status(201).json({
      success: true,
      news: result.rows[0]
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "News konnte nicht veröffentlicht werden."
    });

  }

});


/* =========================================
   NEWS BEARBEITEN
   Nur Vorstand
========================================= */

app.put("/api/news/:id", requireAuth, async (req, res) => {

  try {

    const {
      title,
      text,
      image_url
    } = req.body;


    if (!title || !text) {

      return res.status(400).json({
        error: "Überschrift und Text sind erforderlich."
      });

    }


    const result = await pool.query(
      `
      UPDATE news
      SET
        title = $1,
        text = $2,
        image_url = $3,
        updated_at = NOW()
      WHERE id = $4
      RETURNING *
      `,
      [
        title.trim(),
        text.trim(),
        image_url || null,
        req.params.id
      ]
    );


    if (result.rows.length === 0) {

      return res.status(404).json({
        error: "News nicht gefunden."
      });

    }


    res.json({
      success: true,
      news: result.rows[0]
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "News konnte nicht bearbeitet werden."
    });

  }

});


/* =========================================
   NEWS LÖSCHEN
   Nur Vorstand
========================================= */

app.delete("/api/news/:id", requireAuth, async (req, res) => {

  try {

    const result = await pool.query(
      `
      DELETE FROM news
      WHERE id = $1
      RETURNING id
      `,
      [req.params.id]
    );


    if (result.rows.length === 0) {

      return res.status(404).json({
        error: "News nicht gefunden."
      });

    }


    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "News konnte nicht gelöscht werden."
    });

  }

});


/* =========================================
   SERVER START
========================================= */

async function startServer() {

  try {

    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {

      console.log(
        `Fenerbahçe Marl Backend läuft auf Port ${PORT}`
      );

    });

  } catch (error) {

    console.error(
      "Server konnte nicht gestartet werden:",
      error
    );

    process.exit(1);

  }

}


startServer();
