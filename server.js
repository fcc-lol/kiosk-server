const express = require("express");
const { createServer } = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { MongoClient } = require("mongodb");
const http = require("http");

const dotenv = require("dotenv");
dotenv.config();

const corsOptions = {
  origin: [
    "https://kiosk.fcc.lol",
    "http://localhost:3000",
    "http://localhost:5173"
  ],
  methods: ["GET", "POST"],
  credentials: true
};

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: corsOptions
});

app.use(cors(corsOptions));

let currentUrl = null;

function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

io.on("connection", (socket) => {
  if (currentUrl) {
    socket.emit("currentUrlState", currentUrl);
  }

  socket.on("changeUrl", (url) => {
    try {
      if (!url) {
        socket.emit("error", "URL cannot be empty");
        return;
      }

      if (!isValidUrl(url)) {
        socket.emit("error", "Invalid URL format");
        return;
      }

      currentUrl = url;

      io.emit("currentUrlState", url);
    } catch (error) {
      socket.emit("error", "Failed to process URL change");
    }
  });

  socket.on("requestCurrentUrl", () => {
    socket.emit("currentUrlState", currentUrl);
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", connections: io.engine.clientsCount });
});

const mongoUrl = process.env.MONGO_DB_URL;
let db;

MongoClient.connect(mongoUrl, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then((client) => {
    db = client.db("main");
    httpServer.listen(process.env.PORT || 3000, () => {
      console.log(`Server is running on port ${process.env.PORT || 3000}`);
    });
  })
  .catch((error) => {
    console.error("Failed to connect to MongoDB:", error);
    process.exit(1);
  });

app.get("/urls", async (req, res) => {
  const apiKey = req.query["fccApiKey"];
  if (!apiKey || apiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  try {
    if (!db) {
      console.error("Database connection is not established");
      return res
        .status(500)
        .json({ error: "Database connection not established" });
    }

    const urlsCollection = db.collection("urls");
    const urls = await urlsCollection.find().toArray();

    if (urls.length === 0) {
      console.warn("No URLs found in the collection");
    }

    res.json(urls);
  } catch (error) {
    console.error("Error fetching URLs:", error);
    res.status(500).json({ error: "Failed to fetch URLs" });
  }
});
