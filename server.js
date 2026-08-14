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

  /* =========================================
     NEWS
  ========================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS news (
      id SERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      text TEXT NOT NULL,
      image_url TEXT,
      image_position_x INTEGER DEFAULT 50,
      image_position_y INTEGER DEFAULT 50,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    ALTER TABLE news
    ADD COLUMN IF NOT EXISTS image_position_x INTEGER DEFAULT 50;
  `);

  await pool.query(`
    ALTER TABLE news
    ADD COLUMN IF NOT EXISTS image_position_y INTEGER DEFAULT 50;
  `);


  /* =========================================
     MANNSCHAFTEN
  ========================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS teams (
      id SERIAL PRIMARY KEY,
      slug VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      image_url TEXT,
      image_public_id TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);


  /* =========================================
     SPIELER
  ========================================= */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id SERIAL PRIMARY KEY,
      team_id INTEGER NOT NULL
        REFERENCES teams(id)
        ON DELETE CASCADE,

      shirt_number VARCHAR(10),
      name VARCHAR(150) NOT NULL,

      position_group VARCHAR(50),
      position VARCHAR(100),

      sort_order INTEGER DEFAULT 0,

      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);


  /* =========================================
     3 MANNSCHAFTEN AUTOMATISCH ANLEGEN
  ========================================= */

  await pool.query(`
    INSERT INTO teams (
      slug,
      name
    )
    VALUES
      ('erste-mannschaft', '1. Mannschaft'),
      ('zweite-mannschaft', '2. Mannschaft'),
      ('dritte-mannschaft', '3. Mannschaft')
    ON CONFLICT (slug) DO NOTHING;
  `);


  console.log("News- und Team-Datenbank bereit.");
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
   MANNSCHAFT LADEN
   Öffentlich
========================================= */

app.get("/api/teams/:slug", async (req, res) => {

  try {

    const teamResult = await pool.query(
      `
      SELECT
        id,
        slug,
        name,
        image_url
      FROM teams
      WHERE slug = $1
      `,
      [req.params.slug]
    );


    if (teamResult.rows.length === 0) {

      return res.status(404).json({
        error: "Mannschaft nicht gefunden."
      });

    }


    const team = teamResult.rows[0];


    const playersResult = await pool.query(
      `
      SELECT
        id,
        shirt_number,
        name,
        position_group,
        position,
        sort_order
      FROM players
      WHERE team_id = $1
      ORDER BY
        CASE position_group
          WHEN 'Torwart' THEN 1
          WHEN 'Abwehr' THEN 2
          WHEN 'Mittelfeld' THEN 3
          WHEN 'Sturm' THEN 4
          ELSE 5
        END,
        sort_order ASC,
        id ASC
      `,
      [team.id]
    );


    res.json({
      ...team,
      players: playersResult.rows
    });


  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Mannschaft konnte nicht geladen werden."
    });

  }

});


/* =========================================
   SPIELER SPEICHERN
   Nur Vorstand
========================================= */

app.put(
  "/api/teams/:slug/players",
  requireAuth,
  async (req, res) => {

    const client = await pool.connect();

    try {

      const players = req.body.players;


      if (!Array.isArray(players)) {

        return res.status(400).json({
          error: "Spielerliste fehlt."
        });

      }


      const teamResult = await client.query(
        `
        SELECT id
        FROM teams
        WHERE slug = $1
        `,
        [req.params.slug]
      );


      if (teamResult.rows.length === 0) {

        return res.status(404).json({
          error: "Mannschaft nicht gefunden."
        });

      }


      const teamId = teamResult.rows[0].id;


      await client.query("BEGIN");


      await client.query(
        `
        DELETE FROM players
        WHERE team_id = $1
        `,
        [teamId]
      );


      for (let i = 0; i < players.length; i++) {

        const player = players[i];


        const name =
          String(player.name || "").trim();

        const shirtNumber =
          String(player.shirt_number || "").trim();

        const positionGroup =
          String(player.position_group || "").trim();

        const position =
          String(player.position || "").trim();


        if (!name) {
          continue;
        }


        await client.query(
          `
          INSERT INTO players (
            team_id,
            shirt_number,
            name,
            position_group,
            position,
            sort_order
          )
          VALUES ($1, $2, $3, $4, $5, $6)
          `,
          [
            teamId,
            shirtNumber || null,
            name,
            positionGroup || null,
            position || null,
            i
          ]
        );

      }


      await client.query("COMMIT");


      res.json({
        success: true
      });


    } catch (error) {

      await client.query("ROLLBACK");

      console.error(error);

      res.status(500).json({
        error: "Spieler konnten nicht gespeichert werden."
      });


    } finally {

      client.release();

    }

  }
);

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
  image_position_x,
  image_position_y,
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
  image_position_x,
  image_position_y,
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
      image_url,
      image_position_x,
      image_position_y
    } = req.body;


    if (!title || !text) {

      return res.status(400).json({
        error: "Überschrift und Text sind erforderlich."
      });

    }


    const rawPositionX =
  Number.isFinite(Number(image_position_x))
    ? Number(image_position_x)
    : 50;

const rawPositionY =
  Number.isFinite(Number(image_position_y))
    ? Number(image_position_y)
    : 50;

const positionX = Math.round(
  Math.max(0, Math.min(100, rawPositionX))
);

const positionY = Math.round(
  Math.max(0, Math.min(100, rawPositionY))
);


    const result = await pool.query(
      `
      INSERT INTO news (
        title,
        text,
        image_url,
        image_position_x,
        image_position_y
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [
        title.trim(),
        text.trim(),
        image_url || null,
        positionX,
        positionY
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
      image_url,
      image_position_x,
      image_position_y
    } = req.body;


    if (!title || !text) {

      return res.status(400).json({
        error: "Überschrift und Text sind erforderlich."
      });

    }


    const rawPositionX =
  Number.isFinite(Number(image_position_x))
    ? Number(image_position_x)
    : 50;

const rawPositionY =
  Number.isFinite(Number(image_position_y))
    ? Number(image_position_y)
    : 50;

const positionX = Math.round(
  Math.max(0, Math.min(100, rawPositionX))
);

const positionY = Math.round(
  Math.max(0, Math.min(100, rawPositionY))
);


    const result = await pool.query(
      `
      UPDATE news
      SET
        title = $1,
        text = $2,
        image_url = $3,
        image_position_x = $4,
        image_position_y = $5,
        updated_at = NOW()
      WHERE id = $6
      RETURNING *
      `,
      [
        title.trim(),
        text.trim(),
        image_url || null,
        positionX,
        positionY,
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
   KONTAKTFORMULAR
========================================= */

app.post("/api/contact", async (req, res) => {

  try {

    const {
      name,
      email,
      subject,
      message
    } = req.body;


    if (!name || !email || !subject || !message) {

      return res.status(400).json({
        error: "Bitte alle Felder ausfüllen."
      });

    }


    const emailRegex =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


    if (!emailRegex.test(email)) {

      return res.status(400).json({
        error: "Bitte eine gültige E-Mail-Adresse eingeben."
      });

    }


    const cleanName =
      String(name).trim().slice(0, 100);

    const cleanEmail =
      String(email).trim().slice(0, 200);

    const cleanSubject =
      String(subject).trim().slice(0, 200);

    const cleanMessage =
      String(message).trim().slice(0, 5000);


    const resendResponse = await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",

        headers: {
          "Authorization":
            `Bearer ${process.env.RESEND_API_KEY}`,

          "Content-Type":
            "application/json",

          "User-Agent":
            "Fenerbahce-Marl-Website/1.0"
        },

        body: JSON.stringify({

          from:
  "Fenerbahçe Marl <website@fenerbahce-marl.de>",

to: [
  "vorstand@fenerbahce-marl.de"
],

reply_to: cleanEmail,

subject:
  `Kontaktformular: ${cleanSubject}`,

          text:
`Neue Nachricht über die Website von Fenerbahçe Marl

Name:
${cleanName}

E-Mail:
${cleanEmail}

Betreff:
${cleanSubject}

Nachricht:
${cleanMessage}`

        })

      }
    );


    const data =
      await resendResponse.json();


    if (!resendResponse.ok) {

      console.error(
        "Resend Fehler:",
        data
      );

      return res.status(500).json({
        error: "E-Mail konnte nicht gesendet werden."
      });

    }


    res.json({
      success: true,
      message: "Nachricht wurde gesendet."
    });


  } catch (error) {

    console.error(
      "Kontaktformular Fehler:",
      error
    );

    res.status(500).json({
      error: "Nachricht konnte nicht gesendet werden."
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
