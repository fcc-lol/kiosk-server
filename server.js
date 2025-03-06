const express = require("express");
const { createServer } = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: "*", // In production, replace with specific origin
    methods: ["GET", "POST"]
  }
});

// Enable CORS for Express routes
app.use(cors());

// Keep track of the current URL
let currentUrl = null;

// URL validation function
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

// Socket.IO connection handling
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  // Send current URL to newly connected client
  if (currentUrl) {
    socket.emit("currentUrlState", currentUrl);
  }

  // Handle URL change requests
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
      console.log(`URL changed to: ${url}`);

      // Broadcast to all clients (including sender)
      io.emit("currentUrlState", url);
    } catch (error) {
      console.error("Error handling URL change:", error);
      socket.emit("error", "Failed to process URL change");
    }
  });

  // Handle client requesting current URL
  socket.on("requestCurrentUrl", () => {
    socket.emit("currentUrlState", currentUrl);
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

// Basic health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", connections: io.engine.clientsCount });
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
