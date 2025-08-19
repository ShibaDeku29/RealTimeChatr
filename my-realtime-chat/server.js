const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, "public")));

io.on("connection", (socket) => {
  console.log("user connected:", socket.id);

  socket.on("join", (name) => {
    socket.data.name = name || "Ẩn danh";
    io.emit("system", `${socket.data.name} đã tham gia!`);
  });

  socket.on("msg", (text) => {
    const payload = {
      name: socket.data.name || "Ẩn danh",
      text: text,
      ts: new Date().toLocaleTimeString()
    };
    io.emit("msg", payload);
  });

  socket.on("disconnect", () => {
    if (socket.data.name) {
      io.emit("system", `${socket.data.name} đã rời đi`);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
