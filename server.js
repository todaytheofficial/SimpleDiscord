// --- Server Setup and Dependencies ---
const express = require('express');
const http = require('http');
const socketio = require('socket.io');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketio(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'SDAF@KL#$KLJ#@%(*$@%(@#$JNFDSJKRF@#*$@#&*$FDSFDS'; // CHANGE THIS IN PRODUCTION!

// --- Middleware and Setup ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname))); 

// Create folders for uploads and default images
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR);
}
// Serve uploaded files from /uploads route
app.use('/uploads', express.static(UPLOAD_DIR));

// Multer storage configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const userId = req.user ? req.user.userId : 'temp'; 
        cb(null, `${userId}_${Date.now()}${path.extname(file.originalname)}`);
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
    { id: 101, username: 'testuser', password: 'password', avatar: '/img/anon_blue.png' },
    { id: 102, username: 'friend_one', password: 'password', avatar: '/img/anon_green.png' }
];
let channels = []; 
let channelIdCounter = 1001; 
let messageIdCounter = 1;

let friendRequests = {}; 

let friends = {
    101: [102], 
    102: [101]  
};

let userDMChannels = {}; 
let connectedUsers = {}; 

// --- Utility Functions ---

function generateToken(user) {
    return jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
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


// --- API Endpoints: Auth, Profile, and Settings ---

/** POST /api/register - Register a new user. */
app.post('/api/register', upload.single('avatar'), (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    if (getUserByUsername(username)) return res.status(400).json({ message: 'Username already taken' });

    const newUser = {
        id: users.length + 101,
        username: username,
        password: password, 
        avatar: req.file ? `/uploads/${req.file.filename}` : '/img/anon_blue.png'
    };
    users.push(newUser);
    res.status(201).json({ message: 'User registered successfully.' });
});

/** POST /api/login - Authenticate and return JWT. */
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = getUserByUsername(username);
    
    if (!user || user.password !== password) { 
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // --- ИСПРАВЛЕНИЕ: Генерируем новый токен для обновления localStorage клиента
    const token = generateToken(user);
    
    // Инициализация DM-каналов для старых аккаунтов при логине
    (friends[user.id] || []).forEach(friendId => {
         createDMChannel(user.id, friendId);
    });

    res.json({ token, userId: user.id, username: user.username, avatar: user.avatar });
});

/** GET /api/profile/:userId - Get public profile data. */
app.get('/api/profile/:userId', async (req, res) => {
    const userId = parseInt(req.params.userId);
    const user = getUserById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    const status = connectedUsers[userId] ? 'online' : 'offline';

    res.json({ 
        userId: user.id, 
        username: user.username, 
        avatar: user.avatar,
        status: status 
    });
});

/** POST /api/update-profile - Update username and/or avatar. */
app.post('/api/update-profile', verifyToken, upload.single('avatar'), (req, res) => {
    const userId = req.user.userId;
    const user = getUserById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const { newUsername } = req.body;
    let updatedUsername = user.username;
    let updatedAvatar = user.avatar;

    if (newUsername && newUsername !== user.username) {
        if (getUserByUsername(newUsername)) {
            return res.status(400).json({ message: 'New username is already taken.' });
        }
        user.username = newUsername;
        updatedUsername = newUsername;
    }

    if (req.file) {
        if (user.avatar && !user.avatar.startsWith('/img/')) { 
             try { fs.unlinkSync(path.join(__dirname, user.avatar)); } catch (e) { /* silent fail */ }
        }
        user.avatar = `/uploads/${req.file.filename}`; 
        updatedAvatar = user.avatar;
    }

    io.emit('userUpdateInfo', { 
        userId: user.id, 
        newUsername: updatedUsername, 
        newAvatar: updatedAvatar 
    });

    res.json({ 
        message: 'Profile updated',
        newUsername: updatedUsername,
        newAvatar: updatedAvatar
    });
});

/** POST /api/delete-account - Permanently delete the user account. */
app.post('/api/delete-account', verifyToken, (req, res) => {
    const userId = req.user.userId;
    const userIndex = users.findIndex(u => u.id === userId);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'Account not found.' });
    }

    const deletedUser = users.splice(userIndex, 1)[0];

    delete friends[userId];
    for (const friendId in friends) {
        friends[friendId] = friends[friendId].filter(id => id !== userId);
    }
    delete friendRequests[userId];
    for (const senderId in friendRequests) {
        delete friendRequests[senderId][userId];
    }
    for (const partnerId in userDMChannels[userId]) {
        const channelIdToDelete = userDMChannels[userId][partnerId];
        channels = channels.filter(c => c.id !== channelIdToDelete);
    }
    delete userDMChannels[userId];
    
    if (deletedUser.avatar && !deletedUser.avatar.startsWith('/img/')) {
        try { fs.unlinkSync(path.join(__dirname, deletedUser.avatar)); } catch (e) { /* silent fail */ }
    }

    if (connectedUsers[userId]) {
        connectedUsers[userId].emit('accountDeleted');
        delete connectedUsers[userId];
    }
    
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
            currentUser = getUserById(decoded.userId);
            if (currentUser) {
                socket.join(`user_${currentUser.id}`);
                connectedUsers[currentUser.id] = socket;
                
                // --- ИСПРАВЛЕНИЕ: Перезагрузка данных при аутентификации для исправления кнопок заявок/друзей
                const userFriends = (friends[currentUser.id] || []).map(friendId => {
                    const friend = getUserById(friendId);
                    const dmChannel = createDMChannel(currentUser.id, friendId);

                    return {
                        userId: friend.id,
                        username: friend.username,
                        avatar: friend.avatar,
                        channelId: dmChannel.id
                    };
                });
                
                const incomingRequests = Object.keys(friendRequests).filter(key => {
                    const requesterId = parseInt(key);
                    // Проверяем, что запрос существует и имеет статус 'pending'
                    return friendRequests[requesterId] && friendRequests[requesterId][currentUser.id] === 'pending';
                }).map(requesterId => {
                    const requester = getUserById(parseInt(requesterId));
                    return {
                        userId: requester.id,
                        username: requester.username,
                        avatar: requester.avatar
                    };
                });
                
                // Если нет активного чата, выбираем первый DM канал
                if (currentChatId === 0 && userFriends.length > 0) {
                     currentChatId = userFriends[0].channelId;
                }
                
                if (currentChatId !== 0) {
                     socket.join(`channel_${currentChatId}`);
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
                socket.emit('requestError', 'Authentication failed.');
                socket.disconnect();
            }
        } catch (e) {
            socket.emit('requestError', 'Invalid token.'); // Эту ошибку мы хотим исправить
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

        if (!recipient || recipient.id === currentUser.id) {
            return socket.emit('requestError', 'User not found or cannot send request to self.');
        }

        const isFriend = (friends[currentUser.id] || []).includes(recipient.id);
        if (isFriend) return socket.emit('requestError', 'You are already friends with this user.');
        
        friendRequests[currentUser.id] = friendRequests[currentUser.id] || {};
        if (friendRequests[currentUser.id][recipient.id] === 'pending') {
            return socket.emit('requestError', 'Friend request already sent.');
        }

        friendRequests[recipient.id] = friendRequests[recipient.id] || {};
        if (friendRequests[recipient.id][currentUser.id] === 'pending') {
             // Если получатель уже отправил запрос, автоматически принимаем его.
             
             // 1. Добавляем в друзья
             friends[currentUser.id] = friends[currentUser.id] || [];
             friends[recipient.id] = friends[recipient.id] || [];
             friends[currentUser.id].push(recipient.id);
             friends[recipient.id].push(currentUser.id);
             
             // 2. Создаем канал и удаляем запрос
             const dmChannel = createDMChannel(currentUser.id, recipient.id);
             delete friendRequests[recipient.id][currentUser.id];
             
             socket.emit('requestSuccess', `Automatically accepted request from ${recipientUsername}.`);
             if (connectedUsers[recipient.id]) {
                 connectedUsers[recipient.id].emit('friendRequestAccepted', {
                     userId: currentUser.id,
                     username: currentUser.username,
                     avatar: currentUser.avatar,
                     channelId: dmChannel.id
                 });
             }
             // Переаутентификация для обновления списка друзей у себя
             socket.emit('authenticate', generateToken(currentUser)); 
             return;
        }
        
        // Save new request
        friendRequests[currentUser.id][recipient.id] = 'pending';
        socket.emit('requestSuccess', `Friend request sent to ${recipientUsername}.`);

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

            if (!friends[senderId].includes(recipientId)) {
                friends[senderId].push(recipientId);
            }
            if (!friends[recipientId].includes(senderId)) {
                friends[recipientId].push(senderId);
            }
            
            const dmChannel = createDMChannel(senderId, recipientId);
            
            delete friendRequests[senderId][recipientId];

            socket.emit('requestSuccess', `Accepted request from ${sender.username}.`);
            
            if (connectedUsers[senderId]) {
                connectedUsers[senderId].emit('friendRequestAccepted', {
                    userId: recipientId,
                    username: currentUser.username,
                    avatar: currentUser.avatar,
                    channelId: dmChannel.id
                });
            }
            
            // --- ИСПРАВЛЕНИЕ: Переаутентификация для обновления списков друзей
            socket.emit('authenticate', generateToken(currentUser)); 

        } else if (action === 'reject') {
            delete friendRequests[senderId][recipientId];
            socket.emit('requestSuccess', `Rejected request from ${sender.username}.`);
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
    console.log(`Server running on http://localhost:${PORT}`);
});