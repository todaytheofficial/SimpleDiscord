// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// --- КОНФИГУРАЦИЯ ---
const JWT_SECRET = process.env.JWT_SECRET || 'YOUR_SQLITE_SECRET_KEY_12345'; 
const PORT = process.env.PORT || 3000;

// Инициализация SQLite: база данных будет в файле chaoticord.db
const db = new sqlite3.Database('chaoticcord.db', (err) => {
    if (err) {
        console.error('Ошибка подключения SQLite:', err.message);
    } else {
        console.log('SQLite успешно подключена к chaoticord.db');
        initializeDatabase();
    }
});

// Обертка для асинхронных SQL-запросов
const dbRun = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
};

const dbGet = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

const dbAll = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
};

// --- ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ (СОЗДАНИЕ ТАБЛИЦ) ---

async function initializeDatabase() {
    try {
        await dbRun(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                avatar TEXT DEFAULT '/img/default_chaos.png',
                status TEXT DEFAULT 'offline'
            );
        `);
        // Таблица для отслеживания дружбы и запросов
        await dbRun(`
            CREATE TABLE IF NOT EXISTS friends (
                user_id INTEGER,
                friend_id INTEGER,
                status TEXT DEFAULT 'pending', -- accepted, pending
                PRIMARY KEY (user_id, friend_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (friend_id) REFERENCES users(id)
            );
        `);
        console.log('SQLite: Таблицы пользователей и друзей готовы.');
    } catch (err) {
        console.error('Ошибка создания таблиц:', err.message);
    }
}

// Middleware
app.use(express.json());
app.use(express.static('public')); 
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Хранилище: userId -> socketId 
const userSocketMap = {}; 

// --- EXPRESS МАРШРУТЫ ДЛЯ АУТЕНТИФИКАЦИИ ---

// 1. Регистрация
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: 'Имя и пароль обязательны.' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await dbRun('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        res.status(201).json({ message: 'Регистрация успешна.' });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'Это имя пользователя уже занято.' });
        }
        res.status(500).json({ message: 'Ошибка регистрации.' });
    }
});

// 2. Вход
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: 'Неверное имя пользователя или пароль.' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, userId: user.id, username: user.username, avatar: user.avatar });
});

// --- SOCKET.IO ЛОГИКА ---

io.on('connection', (socket) => {
    let currentUserId = null; 
    let currentUsername = null;

    // 1. Аутентификация
    socket.on('authenticate', async (token) => {
        if (!token) return socket.disconnect();

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            currentUserId = decoded.userId;
            currentUsername = decoded.username;

            userSocketMap[currentUserId] = socket.id;
            await dbRun('UPDATE users SET status = ? WHERE id = ?', ['online', currentUserId]);
            
            console.log(`User ${currentUsername} connected.`);
            io.emit('userStatusUpdate', { userId: currentUserId, username: currentUsername, status: 'online' });
            
        } catch (err) {
            console.log('Socket authentication failed:', err.message);
            socket.disconnect(); 
        }
    });
    
    // 2. Отправка сообщения
    socket.on('chat message', (data) => {
        if (!currentUserId || !data.content) return; 
        
        io.emit('newMessage', {
            username: currentUsername,
            content: data.content,
            avatar: '/img/default_chaos.png' 
        }); 
    });


    // 3. Отправка запроса на добавление в друзья
    socket.on('sendFriendRequest', async ({ recipientUsername }) => {
        if (!currentUserId) return socket.emit('requestError', 'Необходимо войти.');
        
        const recipient = await dbGet('SELECT id FROM users WHERE username = ?', [recipientUsername]);
        if (!recipient) return socket.emit('requestError', 'Пользователь не найден.');
        
        const recipientId = recipient.id;

        if (recipientId === currentUserId) return socket.emit('requestError', 'Нельзя добавить самого себя.');
        
        // Проверка: уже друзья (двусторонний поиск) или запрос уже существует
        const existingRelation = await dbGet(
            'SELECT status FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', 
            [currentUserId, recipientId, recipientId, currentUserId]
        );

        if (existingRelation && existingRelation.status === 'accepted') {
             return socket.emit('requestError', 'Вы уже друзья.');
        }
        if (existingRelation && existingRelation.status === 'pending') {
             return socket.emit('requestError', 'Запрос уже отправлен или находится в ожидании.');
        }

        // Вставляем запрос: user_id (отправитель) -> friend_id (получатель) со статусом 'pending'
        await dbRun('INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)', [currentUserId, recipientId, 'pending']);

        // Уведомляем получателя
        const recipientSocketId = userSocketMap[recipientId];
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('newFriendRequest', { 
                senderId: currentUserId,
                senderUsername: currentUsername 
            });
        }
        socket.emit('requestSuccess', `Запрос другу ${recipientUsername} отправлен.`);
    });


    // 4. Принятие запроса
    socket.on('acceptFriendRequest', async ({ senderId }) => {
        if (!currentUserId) return socket.emit('requestError', 'Необходимо войти.');
        
        const senderUser = await dbGet('SELECT username FROM users WHERE id = ?', [senderId]);
        if (!senderUser) return;
        
        // 1. Обновляем статус запроса от отправителя
        await dbRun(
            'UPDATE friends SET status = ? WHERE user_id = ? AND friend_id = ? AND status = ?',
            ['accepted', senderId, currentUserId, 'pending']
        );
        
        // 2. Создаем обратную запись (теперь они друзья в обоих направлениях)
        // Проверка, чтобы не создать дубликат
        const reverseRelation = await dbGet('SELECT * FROM friends WHERE user_id = ? AND friend_id = ?', [currentUserId, senderId]);
        if (!reverseRelation) {
            await dbRun('INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)', [currentUserId, senderId, 'accepted']);
        }
        
        // Уведомляем обоих
        socket.emit('friendAccepted', senderUser.username);
        const senderSocketId = userSocketMap[senderId];
        if (senderSocketId) {
             io.to(senderSocketId).emit('friendAccepted', currentUsername);
        }
    });


    // 5. Отключение
    socket.on('disconnect', async () => {
        if (currentUserId) {
            delete userSocketMap[currentUserId];
            await dbRun('UPDATE users SET status = ? WHERE id = ?', ['offline', currentUserId]);
            io.emit('userStatusUpdate', { userId: currentUserId, username: currentUsername, status: 'offline' });
        }
    });
});

server.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});