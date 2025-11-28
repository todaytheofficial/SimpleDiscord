// --- Server Setup and Dependencies ---
const express = require('express');
const http = require('http');
const socketio = require('socket.io');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises; // Используем fs.promises для асинхронных операций с файлами

const app = express();
const server = http.createServer(app);
const io = socketio(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'fdsfjsdklk$!#JH$@KLHJ$LASKDASJKFHdsnmfk'; // !!! CHANGE THIS IN PRODUCTION !!!

// --- Middleware and Setup ---
const UPLOAD_DIR = path.join(__dirname, 'uploads');
// Проверка и создание директории асинхронно
fs.mkdir(UPLOAD_DIR, { recursive: true }).catch(console.error);

app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname))); 

// Multer storage configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    // Временно называем файл, окончательное имя дадим после регистрации/аутентификации
    filename: (req, file, cb) => {
        // req.user может быть null при регистрации, используем временный префикс
        const prefix = req.user ? req.user.userId : 'temp_reg'; 
        cb(null, `${prefix}_${Date.now()}${path.extname(file.originalname)}`);
    }
});
const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
}); 

// --- In-Memory Database Simulation ---
let users = [
    // --- АККАУНТ АДМИНИСТРАТОРА (Создателя) ---
    { id: 100, username: 'Today_Idk', password: 'adminpassword', avatar: '/img/anon_red.png', isAdmin: true, isBlocked: false }, 
    // ------------------------------------------
    { id: 101, username: 'testuser', password: 'password', avatar: '/img/anon_blue.png', isAdmin: false, isBlocked: false },
    { id: 102, username: 'friend_one', password: 'password', avatar: '/img/anon_green.png', isAdmin: false, isBlocked: false }
];
let channels = []; 
let channelIdCounter = 1001; 
let messageIdCounter = 1;
let userIdCounter = 103; // Для новых пользователей

let friendRequests = {}; 
let friends = {
    101: [102], 
    102: [101] 
};

let userDMChannels = {}; 
let connectedUsers = {}; 

// --- Utility Functions ---

function generateToken(user) {
    return jwt.sign({ userId: user.id, username: user.username, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1d' });
}

function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Invalid token format' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Token is invalid or expired' });
        req.user = decoded;
        next();
    });
}

function getUserById(id) {
    return users.find(u => u.id === id);
}

function getUserByUsername(username) {
    return users.find(u => u.username === username);
}

function getChannelById(id) {
    return channels.find(c => c.id === id);
}

function createDMChannel(user1Id, user2Id) {
    const existingDmId = userDMChannels[user1Id]?.[user2Id] || userDMChannels[user2Id]?.[user1Id];
    if (existingDmId) {
        const existingChannel = getChannelById(existingDmId);
        if (existingChannel) return existingChannel;
    }

    const channelName = `dm_${user1Id}_${user2Id}`;
    const channel = {
        id: channelIdCounter++,
        name: channelName,
        isDM: true,
        messages: [], 
        members: [user1Id, user2Id]
    };
    channels.push(channel);

    userDMChannels[user1Id] = userDMChannels[user1Id] || {};
    userDMChannels[user2Id] = userDMChannels[user2Id] || {};
    userDMChannels[user1Id][user2Id] = channel.id;
    userDMChannels[user2Id][user1Id] = channel.id;

    return channel;
}

/** Broadcasts an announcement message to all connected users. */
function broadcastAnnouncement(message) {
    const announcement = {
        id: messageIdCounter++,
        channelId: 0, 
        user_id: 100, 
        username: 'SYSTEM ANNOUNCEMENT',
        avatar: '/img/anon_red.png',
        content: message,
        timestamp: Date.now(),
        isDM: 0 
    };
    
    io.emit('systemAnnouncement', announcement); 
    console.log(`[ADMIN] Announcement: ${message}`);
}

// --- API Endpoints ---

/** POST /api/register - Register a new user. */
app.post('/api/register', (req, res, next) => {
    // Временный middleware для регистрации: req.user еще не существует
    upload.single('avatar')(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ message: err.message });
        } else if (err) {
            return res.status(400).json({ message: err.message });
        }
        
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: 'Username and password are required' });
        if (getUserByUsername(username)) return res.status(400).json({ message: 'Username is already taken' });

        const newUserId = userIdCounter++;
        const newUser = {
            id: newUserId,
            username: username,
            password: password, 
            avatar: '/img/anon_blue.png', // Default
            isAdmin: false,
            isBlocked: false
        };
        
        // Rename temp file if registration was successful
        if (req.file) {
            const oldPath = req.file.path;
            const newFilename = `${newUserId}_${Date.now()}${path.extname(req.file.originalname)}`;
            const newPath = path.join(UPLOAD_DIR, newFilename);
            
            try {
                await fs.rename(oldPath, newPath);
                newUser.avatar = `/uploads/${newFilename}`;
            } catch (err) {
                console.error('Error renaming file during registration:', err);
            }
        }

        users.push(newUser);

        res.status(201).json({ message: 'User successfully registered.' });
    });
});


/** POST /api/login - Authenticate and return JWT. */
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = getUserByUsername(username);
    
    if (!user || user.password !== password) { 
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    if (user.isBlocked) {
         return res.status(403).json({ message: 'Your account has been blocked by an administrator.' });
    }

    const token = generateToken(user);
    
    // Initialization of DM channels for existing friends
    (friends[user.id] || []).forEach(friendId => {
         createDMChannel(user.id, friendId);
    });

    res.json({ 
        token, 
        userId: user.id, 
        username: user.username, 
        avatar: user.avatar,
        isAdmin: user.isAdmin || false 
    });
});


/** POST /api/update-profile - Update user profile data (username, avatar). */
app.post('/api/update-profile', verifyToken, upload.single('avatar'), async (req, res) => {
    const userId = req.user.userId;
    const user = getUserById(userId);

    if (!user) {
        return res.status(404).json({ message: 'User not found.' });
    }

    let newUsername = req.body.newUsername;
    let newAvatar = user.avatar;
    let changesMade = false;

    // 1. Handle Username Update
    if (newUsername && newUsername !== user.username) {
        const existingUser = getUserByUsername(newUsername);
        if (existingUser && existingUser.id !== userId) {
            return res.status(400).json({ message: 'Username is already taken.' });
        }
        user.username = newUsername;
        changesMade = true;
    }

    // 2. Handle Avatar Update
    if (req.file) {
        // Удаляем старый аватар, если это не дефолтный файл
        if (user.avatar && !user.avatar.includes('/img/anon_')) {
            const oldAvatarPath = path.join(__dirname, user.avatar);
            try {
                await fs.unlink(oldAvatarPath);
            } catch (err) {
                if (err.code !== 'ENOENT') console.error('Error deleting old avatar:', err); // Ignore if file not found
            }
        }
        
        // Переименовываем новый файл
        const oldPath = req.file.path;
        const newFilename = `${user.id}_${Date.now()}${path.extname(req.file.originalname)}`;
        const newPath = path.join(UPLOAD_DIR, newFilename);
        
        try {
            await fs.rename(oldPath, newPath);
            newAvatar = `/uploads/${newFilename}`;
            user.avatar = newAvatar;
            changesMade = true;
        } catch (err) {
            console.error('Error renaming new avatar:', err);
            return res.status(500).json({ message: 'Failed to save new avatar.' });
        }
    }

    if (changesMade) {
        // Уведомляем пользователя о необходимости обновления GUI (через handleProfileUpdateSuccess на клиенте)
        return res.json({ 
            message: 'Profile successfully updated.',
            username: user.username,
            avatar: user.avatar
        });
    }

    res.json({ message: 'No changes detected.' });
});

/** POST /api/delete-account - Delete the user's account. */
app.post('/api/delete-account', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const userIndex = users.findIndex(u => u.id === userId);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found.' });
    }
    
    const userToDelete = users[userIndex];

    // 1. Удаление файлов аватара
    if (userToDelete.avatar && !userToDelete.avatar.includes('/img/anon_')) {
        const avatarPath = path.join(__dirname, userToDelete.avatar);
        try {
            await fs.unlink(avatarPath);
        } catch (err) {
             if (err.code !== 'ENOENT') console.error('Error deleting avatar during account deletion:', err);
        }
    }

    // 2. Удаление из пользователей
    users.splice(userIndex, 1);

    // 3. Удаление из списков друзей и DM-каналов
    delete friends[userId];
    Object.keys(friends).forEach(id => {
        friends[id] = friends[id].filter(friendId => friendId !== userId);
    });

    Object.keys(friendRequests).forEach(id => {
        delete friendRequests[id][userId];
        if (friendRequests[userId]) delete friendRequests[userId][id];
    });

    // 4. Оповещение и отключение
    if (connectedUsers[userId]) {
        connectedUsers[userId].emit('accountDeleted');
        connectedUsers[userId].disconnect(true);
        delete connectedUsers[userId];
    }
    
    // 5. Удаление DM-каналов, связанных с пользователем
    // (В этом простом примере мы оставим каналы, но удалим ссылки)
    delete userDMChannels[userId];
    Object.keys(userDMChannels).forEach(id => {
         delete userDMChannels[id][userId];
    });

    res.json({ message: 'Account successfully deleted.' });
});


// --- Socket.io Handlers: Real-time Communication ---
io.on('connection', (socket) => {
    let currentUser = null;
    let currentChatId = 0; 
    let isChatDM = true;

    socket.on('authenticate', (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = getUserById(decoded.userId);
            
            if (user && !user.isBlocked) {
                currentUser = user;
                // --- ФИКС: Убеждаемся, что сокет присоединен к комнате пользователя ---
                socket.join(`user_${currentUser.id}`);
                connectedUsers[currentUser.id] = socket;
                
                const userFriends = (friends[currentUser.id] || []).map(friendId => {
                    const friend = getUserById(friendId);
                    // Важно: Проверяем, существует ли друг (может быть удален)
                    if (!friend) return null; 
                    const dmChannel = createDMChannel(currentUser.id, friendId);

                    return {
                        userId: friend.id,
                        username: friend.username,
                        avatar: friend.avatar,
                        channelId: dmChannel.id
                    };
                }).filter(f => f !== null); // Удаляем несуществующих друзей
                
                const incomingRequests = Object.keys(friendRequests).filter(key => {
                    const requesterId = parseInt(key);
                    return friendRequests[requesterId] && friendRequests[requesterId][currentUser.id] === 'pending';
                }).map(requesterId => {
                    const requester = getUserById(parseInt(requesterId));
                    if (!requester) return null;
                    return {
                        userId: requester.id,
                        username: requester.username,
                        avatar: requester.avatar
                    };
                }).filter(r => r !== null);
                
                // Переключение на первый DM, если нет активного чата
                if (currentChatId === 0 && userFriends.length > 0) {
                     currentChatId = userFriends[0].channelId;
                }
                
                if (currentChatId !== 0) {
                     socket.join(`channel_${currentChatId}`);
                     // Отправляем историю сообщений сразу
                     const activeChannel = getChannelById(currentChatId);
                     if(activeChannel) socket.emit('messageHistory', activeChannel.messages);
                }

                socket.emit('initialData', {
                    channels: [], 
                    friends: userFriends,
                    dms: userFriends.reduce((acc, f) => { acc[f.userId] = { channelId: f.channelId }; return acc; }, {}),
                    pendingRequests: incomingRequests,
                    activeChatId: currentChatId,
                    isDM: true 
                });
            } else {
                socket.emit('requestError', 'Authentication error or account blocked.');
                socket.disconnect();
            }
        } catch (e) {
            socket.emit('requestError', 'Invalid token.'); 
            socket.disconnect();
        }
    });

    socket.on('joinChat', ({ newId, isDM }) => {
        if (!currentUser || !isDM) return socket.emit('requestError', 'Invalid chat request.');
        
        if (currentChatId !== 0) {
             socket.leave(`channel_${currentChatId}`);
        }
        
        const newChannel = getChannelById(newId);
        if (newChannel && newChannel.isDM) {
            socket.join(`channel_${newChannel.id}`);
            currentChatId = newId;
            isChatDM = true;
            
            socket.emit('chatChanged', { newId, isDM: true });
            socket.emit('messageHistory', newChannel.messages);
        } else {
            currentChatId = 0; 
            isChatDM = true;
            socket.emit('chatChanged', { newId: 0, isDM: true });
            socket.emit('messageHistory', []);
        }
    });

    socket.on('chat message', (data) => {
        if (!currentUser || currentChatId === 0) return socket.emit('requestError', 'Select a friend to message.');

        const channel = getChannelById(currentChatId);
        if (!channel || !channel.isDM) return socket.emit('requestError', 'Invalid DM channel.');

        const message = {
            id: messageIdCounter++,
            channelId: currentChatId,
            user_id: currentUser.id,
            username: currentUser.username,
            avatar: currentUser.avatar,
            content: data.content,
            timestamp: Date.now(),
            isDM: 1
        };

        channel.messages.push(message); 

        io.to(`channel_${currentChatId}`).emit('newMessage', message);
    });

    // --- Friend Request Handlers ---

    socket.on('sendFriendRequest', (recipientUsername) => {
        if (!currentUser) return;
        const recipient = getUserByUsername(recipientUsername);

        if (!recipient) {
            return socket.emit('requestError', `User "${recipientUsername}" not found.`);
        }
        if (recipient.id === currentUser.id) {
            return socket.emit('requestError', 'You cannot send a request to yourself.');
        }
        
        if ((friends[currentUser.id] || []).includes(recipient.id)) {
            return socket.emit('requestError', `${recipient.username} is already your friend.`);
        }
        
        friendRequests[currentUser.id] = friendRequests[currentUser.id] || {};
        friendRequests[recipient.id] = friendRequests[recipient.id] || {};

        if (friendRequests[currentUser.id][recipient.id] === 'pending') {
            return socket.emit('requestError', `Request already sent to ${recipient.username}.`);
        }
        if (friendRequests[recipient.id][currentUser.id] === 'pending') {
            // Auto-Accept Logic (Recipient is the sender, auto-accepts the existing request)
            const senderId = recipient.id;
            const recipientId = currentUser.id;
            
            friends[senderId] = friends[senderId] || [];
            friends[recipientId] = friends[recipientId] || [];

            if (!friends[senderId].includes(recipientId)) { friends[senderId].push(recipientId); }
            if (!friends[recipientId].includes(senderId)) { friends[recipientId].push(senderId); }
            
            const dmChannel = createDMChannel(senderId, recipientId);
            delete friendRequests[senderId][recipientId];

            socket.emit('requestSuccess', `${recipient.username} already sent you a request. Automatically accepted!`);
            
            // --- ФИКС: Принудительное обновление для обоих пользователей ---
            if (connectedUsers[senderId]) {
                 connectedUsers[senderId].emit('authenticate', generateToken(getUserById(senderId))); 
            }
            socket.emit('authenticate', generateToken(currentUser)); 
            return;
        }

        // Send new pending request
        friendRequests[currentUser.id][recipient.id] = 'pending';
        socket.emit('requestSuccess', `Friend request sent to ${recipient.username}.`);

        if (connectedUsers[recipient.id]) {
            connectedUsers[recipient.id].emit('friendRequestReceived', {
                userId: currentUser.id,
                username: currentUser.username,
                avatar: currentUser.avatar
            });
        }
    });

    socket.on('handleFriendRequest', ({ userId, action }) => {
        if (!currentUser) return;
        const senderId = userId; 
        const recipientId = currentUser.id;
        const sender = getUserById(senderId);

        if (!sender) return socket.emit('requestError', 'Sender not found.');

        friendRequests[senderId] = friendRequests[senderId] || {};
        if (friendRequests[senderId][recipientId] !== 'pending') {
            return socket.emit('requestError', 'No pending request from this user.');
        }

        if (action === 'accept') {
            friends[senderId] = friends[senderId] || [];
            friends[recipientId] = friends[recipientId] || [];

            if (!friends[senderId].includes(recipientId)) { friends[senderId].push(recipientId); }
            if (!friends[recipientId].includes(senderId)) { friends[recipientId].push(senderId); }
            
            const dmChannel = createDMChannel(senderId, recipientId);
            delete friendRequests[senderId][recipientId];

            socket.emit('requestSuccess', `Request from ${sender.username} accepted.`);
            
            // --- ФИКС: Принудительное обновление для обоих пользователей ---
            if (connectedUsers[senderId]) {
                 connectedUsers[senderId].emit('authenticate', generateToken(sender)); 
            }
            socket.emit('authenticate', generateToken(currentUser)); 

        } else if (action === 'reject') {
            delete friendRequests[senderId][recipientId];
            socket.emit('requestSuccess', `Request from ${sender.username} rejected.`);
            // Принудительная аутентификация для обновления списка запросов
            socket.emit('authenticate', generateToken(currentUser)); 
        }
    });
    
    // --- АДМИН-ЛОГИКА ---
    socket.on('adminCommand', ({ command, targetUsername, message }) => {
        if (!currentUser || !currentUser.isAdmin) {
            return socket.emit('requestError', 'Access denied. You are not an administrator.');
        }

        const parts = command.trim().toLowerCase().split(' ');
        const cmd = parts[0];
        
        let targetUser = null;
        if (targetUsername) {
            targetUser = getUserByUsername(targetUsername);
        }

        switch (cmd) {
            case 'listusers':
                const userList = users.map(u => 
                    `ID: ${u.id}, Username: ${u.username}, Blocked: ${u.isBlocked}, Online: ${!!connectedUsers[u.id]}`
                ).join('\n');
                socket.emit('requestSuccess', `User List (${users.length}):\n${userList}`);
                break;

            case 'block':
                if (!targetUser) return socket.emit('requestError', `User ${targetUsername} not found.`);
                if (targetUser.id === currentUser.id) return socket.emit('requestError', `Cannot block yourself.`);
                
                targetUser.isBlocked = true;
                socket.emit('requestSuccess', `User ${targetUsername} (ID: ${targetUser.id}) has been blocked.`);
                
                if (connectedUsers[targetUser.id]) {
                    connectedUsers[targetUser.id].emit('requestError', 'Your account has been blocked by an administrator.');
                    connectedUsers[targetUser.id].disconnect(true);
                }
                break;
                
            case 'unblock':
                if (!targetUser) return socket.emit('requestError', `User ${targetUsername} not found.`);
                targetUser.isBlocked = false;
                socket.emit('requestSuccess', `User ${targetUsername} (ID: ${targetUser.id}) has been unblocked.`);
                break;

            case 'announce':
                if (!message) return socket.emit('requestError', 'Announcement message is missing.');
                // Извлекаем полное сообщение, включая пробелы
                const announceMessage = command.substring(command.toLowerCase().indexOf('announce') + 'announce'.length).trim();
                broadcastAnnouncement(announceMessage);
                socket.emit('requestSuccess', 'Announcement broadcasted successfully.');
                break;

            default:
                socket.emit('requestError', `Unknown command: ${cmd}`);
        }
    });

    // --- Disconnect ---
    socket.on('disconnect', () => {
        if (currentUser && connectedUsers[currentUser.id]) {
            delete connectedUsers[currentUser.id];
        }
    });
});

// --- Server Start ---
server.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});