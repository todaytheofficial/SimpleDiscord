// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
// Настройка Socket.io для работы с нашим HTTP-сервером
const io = socketIo(server); 

// Указываем Express, что нужно обслуживать index.html
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Обработка подключений Socket.io
io.on('connection', (socket) => {
  console.log('Пользователь подключился');

  // Обработка события 'chat message' от клиента
  socket.on('chat message', (msg) => {
    // Отправляем сообщение обратно всем подключенным клиентам (включая отправителя)
    io.emit('chat message', msg);
    console.log('Сообщение: ' + msg);
  });

  // Обработка отключения
  socket.on('disconnect', () => {
    console.log('Пользователь отключился');
  });
});

// Запускаем сервер
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});