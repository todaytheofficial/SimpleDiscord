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
const JWT_SECRET = process.env.JWT_SECRET || 'CodeTheApp$#MYscordsecret453@#@$@#_$#__$@#$_%%$%$^#^&$*#%^*#$%#^$%_#$_@ыgdfsgdfsj@#$@#43_#$@$@#$@'; 
const PORT = process.env.PORT || 3000;

// Инициализация SQLite
const db = new sqlite3.Database('chaoticord.db', (err) => {
    if (err) { console.error('Ошибка подключения SQLite:', err.message); } 
    else { console.log('SQLite успешно подключена.'); initializeDatabase(); }
});

// --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ DB (ПРОМИСЫ) ---

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
        // Таблица пользователей (добавлено current_channel_id)
        await dbRun(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                avatar TEXT DEFAULT '/img/default_chaos.png',
                status TEXT DEFAULT 'offline',
                current_channel_id INTEGER DEFAULT 1
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
        // Таблица каналов
        await dbRun(`
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                is_general INTEGER DEFAULT 0 
            );
        `);
        // Таблица сообщений (с channel_id)
         await dbRun(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                channel_id INTEGER,
                username TEXT,
                content TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                avatar TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (channel_id) REFERENCES channels(id)
            );
        `);
        
        // Гарантируем, что #general существует (id=1)
        await dbRun(`
            INSERT OR IGNORE INTO channels (id, name, is_general) 
            VALUES (1, 'general', 1);
        `);
        console.log('SQLite: Таблицы готовы.');
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

// Хранилище: userId -> socketId (для целевых уведомлений и статуса)
const userSocketMap = {}; 


// --- ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ АВАТАРОВ ---

const generateAnonymousAvatar = () => {
    // В идеале: эти файлы должны быть доступны в папке 'public/img/'
    const avatars = ['/img/anon_red.png', '/img/anon_blue.png', '/img/anon_green.png', '/img/anon_yellow.png'];
    return avatars[Math.floor(Math.random() * avatars.length)];
};


// --- EXPRESS МАРШРУТЫ ДЛЯ АУТЕНТИФИКАЦИИ И ПРОФИЛЯ ---

// 1. Регистрация
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, avatar } = req.body; 
        if (!username || !password) return res.status(400).json({ message: 'Имя и пароль обязательны.' });
        
        const userAvatar = avatar || generateAnonymousAvatar(); 
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await dbRun('INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)', [username, hashedPassword, userAvatar]);
        res.status(201).json({ message: 'Регистрация успешна.' });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) return res.status(400).json({ message: 'Это имя пользователя уже занято.' });
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

// 3. Получение данных профиля
app.get('/api/profile/:userId', async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const user = await dbGet('SELECT id, username, avatar, status FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ message: 'Пользователь не найден.' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});


// 4. Обновление профиля
app.post('/api/update_profile', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Необходимо войти.' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId;
        const { newUsername, newAvatar } = req.body;
        
        let updates = [];
        let params = [];
        let usernameChanged = false;
        
        if (newUsername) {
             const existing = await dbGet('SELECT id FROM users WHERE username = ? AND id != ?', [newUsername, userId]);
             if (existing) return res.status(400).json({ message: 'Это имя пользователя уже занято.' });
             updates.push('username = ?');
             params.push(newUsername);
             usernameChanged = true;
        }
        if (newAvatar) {
            updates.push('avatar = ?');
            params.push(newAvatar);
        }

        if (updates.length > 0) {
            params.push(userId);
            await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
            
            if (usernameChanged) {
                const newToken = jwt.sign({ userId: userId, username: newUsername }, JWT_SECRET, { expiresIn: '1d' });
                return res.json({ message: 'Профиль обновлен. Пожалуйста, обновите страницу.', username: newUsername, token: newToken });
            }
            return res.json({ message: 'Профиль обновлен.' });
        }

        res.status(400).json({ message: 'Нет данных для обновления.' });

    } catch (error) {
        res.status(401).json({ message: 'Недействительный токен.' });
    }
});


// --- SOCKET.IO ЛОГИКА ---

io.on('connection', (socket) => {
    let currentUserId = null; 
    let currentUsername = null;
    let currentAvatar = null;
    let currentChannelId = 1; // По умолчанию #general

    // Функция для загрузки и отправки актуальных отношений
    const syncRelations = async () => {
         // Запрос выбирает ID, имя и статус всех, кто связан с текущим пользователем
         const relations = await dbAll(
            `SELECT 
                CASE 
                    WHEN f.user_id = ? THEN f.friend_id 
                    ELSE f.user_id 
                END AS other_user_id,
                u.username,
                f.status 
             FROM friends f
             JOIN users u ON u.id = 
                CASE 
                    WHEN f.user_id = ? THEN f.friend_id 
                    ELSE f.user_id 
                END
             WHERE (f.user_id = ? OR f.friend_id = ?)`,
            [currentUserId, currentUserId, currentUserId, currentUserId]
        );
        
        // Отправляем клиенту
        socket.emit('initialRelations', relations.map(rel => ({
             id: rel.other_user_id,
             username: rel.username,
             status: rel.status
        })));
    };
    
    // Функция для загрузки истории канала
    const loadChannelHistory = async (channelId) => {
        const history = await dbAll('SELECT user_id, username, content, timestamp, avatar FROM messages WHERE channel_id = ? ORDER BY timestamp ASC LIMIT 50', [channelId]);
        socket.emit('messageHistory', history);
    };


    // 1. Аутентификация и синхронизация при подключении
    socket.on('authenticate', async (token) => {
        if (!token) return socket.disconnect();

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            currentUserId = decoded.userId;
            currentUsername = decoded.username;
            
            // Получаем аватар и текущий канал из DB
            const user = await dbGet('SELECT avatar, current_channel_id FROM users WHERE id = ?', [currentUserId]);
            currentAvatar = user.avatar;
            currentChannelId = user.current_channel_id || 1;
            
            // Логика сокет-карты
            if (userSocketMap[currentUserId] && userSocketMap[currentUserId] !== socket.id) {
                 io.sockets.sockets.get(userSocketMap[currentUserId])?.disconnect(true);
            }
            userSocketMap[currentUserId] = socket.id;
            
            await dbRun('UPDATE users SET status = ? WHERE id = ?', ['online', currentUserId]);
            
            // --- СИНХРОНИЗАЦИЯ ДАННЫХ ПРИ СТАРТЕ ---
            
            // A. Загрузка истории канала и присоединение к комнате
            await loadChannelHistory(currentChannelId);
            socket.join(`channel-${currentChannelId}`);
            
            // B. Загрузка всех каналов
            const channels = await dbAll('SELECT id, name FROM channels ORDER BY name ASC');
            socket.emit('initialChannels', { channels: channels, activeChannelId: currentChannelId });

            // C. Загрузка друзей и запросов
            await syncRelations();

            // D. Загрузка всех онлайн-пользователей
            const onlineUsers = await dbAll('SELECT id, username FROM users WHERE status = ? AND id != ?', ['online', currentUserId]);
            socket.emit('initialOnlineUsers', onlineUsers);
            
            // E. Уведомляем всех, что пользователь появился онлайн
            io.emit('userStatusUpdate', { userId: currentUserId, username: currentUsername, status: 'online' });
            
        } catch (err) {
            console.log('Socket authentication failed:', err.message);
            socket.disconnect(); 
        }
    });
    
    // 2. Смена канала
    socket.on('joinChannel', async (newChannelId) => {
        if (!currentUserId) return;
        
        socket.leave(`channel-${currentChannelId}`);
        currentChannelId = parseInt(newChannelId, 10);
        socket.join(`channel-${currentChannelId}`);
        
        await dbRun('UPDATE users SET current_channel_id = ? WHERE id = ?', [currentChannelId, currentUserId]);
        
        await loadChannelHistory(currentChannelId);
        socket.emit('channelChanged', currentChannelId);
    });
    
    // 3. Создание канала
    socket.on('createChannel', async (channelName) => {
        if (!currentUserId || channelName.trim() === '') return socket.emit('requestError', 'Имя канала не может быть пустым.');
        
        const cleanName = channelName.toLowerCase().replace(/\s+/g, '-');
        try {
            const result = await dbRun('INSERT INTO channels (name) VALUES (?)', [cleanName]);
            
            io.emit('newChannelCreated', { id: result.lastID, name: cleanName });
            socket.emit('requestSuccess', `Канал #${cleanName} создан.`);
        } catch (error) {
             socket.emit('requestError', 'Канал с таким именем уже существует.');
        }
    });

    // 4. Отправка сообщения
    socket.on('chat message', async (data) => {
        if (!currentUserId || !data.content || data.content.trim() === '') return; 
        
        const content = data.content.trim();
        const timestamp = new Date().toISOString();

        // Сохранение в DB (используя currentChannelId и currentAvatar)
        await dbRun('INSERT INTO messages (user_id, channel_id, username, content, timestamp, avatar) VALUES (?, ?, ?, ?, ?, ?)', 
            [currentUserId, currentChannelId, currentUsername, content, timestamp, currentAvatar]);

        // Отправка в комнату канала
        io.to(`channel-${currentChannelId}`).emit('newMessage', {
            user_id: currentUserId,
            username: currentUsername,
            content: content,
            timestamp: timestamp,
            avatar: currentAvatar,
            channelId: currentChannelId
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