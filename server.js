// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer'); 
const path = require('path');    
const fs = require('fs');        

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// --- CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET || 'CodeTheApp$#MYscordsecret453@#@$@#_$#__$@#$_%%$%$^#^&$*#%^*#$%#^$%_#$_@ygdfsgdfsj@#$@#43_#$@$@#$@'; 
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('chaoticord.db', (err) => {
    if (err) { console.error('SQLite connection error:', err.message); } 
    else { console.log('SQLite successfully connected.'); initializeDatabase(); }
});

// Setup directories
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const IMG_DIR = path.join(__dirname, 'public', 'img');
if (!fs.existsSync(UPLOAD_DIR)){ fs.mkdirSync(UPLOAD_DIR, { recursive: true }); }
if (!fs.existsSync(IMG_DIR)){ fs.mkdirSync(IMG_DIR, { recursive: true }); }

// --- MULTER CONFIGURATION (File Upload) ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, UPLOAD_DIR); },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) { return cb(null, true); }
        cb(new Error('Only JPEG, PNG, GIF files are allowed!'));
    }
}).single('avatar'); 

// --- DB HELPER FUNCTIONS (Promises) ---
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


// --- DATABASE INITIALIZATION ---
async function initializeDatabase() {
    try {
        await dbRun(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                avatar TEXT DEFAULT '/img/anon_blue.png', 
                status TEXT DEFAULT 'offline',
                current_chat_id INTEGER DEFAULT 1,
                is_dm_active INTEGER DEFAULT 0
            );
        `);
        await dbRun(`
            CREATE TABLE IF NOT EXISTS dm_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER,
                user2_id INTEGER,
                UNIQUE(user1_id, user2_id), 
                FOREIGN KEY (user1_id) REFERENCES users(id),
                FOREIGN KEY (user2_id) REFERENCES users(id)
            );
        `);
        await dbRun(`
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                is_general INTEGER DEFAULT 0 
            );
        `);
         await dbRun(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                channel_id INTEGER,
                username TEXT,
                content TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                avatar TEXT,
                is_dm INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
        
        await dbRun(`
            INSERT OR IGNORE INTO channels (id, name, is_general) 
            VALUES (1, 'general', 1);
        `);
        console.log('SQLite: Tables are ready.');
    } catch (err) {
        console.error('Error creating tables:', err.message);
    }
}

// Middleware
app.use(express.json());
app.use(express.static('public')); 
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Anonymous avatar generator
const generateAnonymousAvatar = () => {
    const avatars = ['/img/anon_blue.png', '/img/anon_green.png', '/img/anon_red.png', '/img/anon_yellow.png'];
    return avatars[Math.floor(Math.random() * avatars.length)];
};

// Storage for User ID -> Socket ID mapping
const userSocketMap = {}; 

// --- EXPRESS ROUTES (API) ---

app.post('/api/register', (req, res) => {
    upload(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ message: 'Upload error: ' + err.message });
        } else if (err) {
            return res.status(400).json({ message: 'Error: ' + err.message });
        }

        const { username, password } = req.body; 
        if (!username || !password) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(400).json({ message: 'Username and password are required.' });
        }
        
        let userAvatar = req.file ? '/uploads/' + req.file.filename : generateAnonymousAvatar();
        
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            
            await dbRun('INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)', [username, hashedPassword, userAvatar]);
            res.status(201).json({ message: 'Registration successful.' });
        } catch (error) {
            if (req.file) fs.unlinkSync(req.file.path); 
            if (error.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ message: 'This username is already taken.' });
            }
            res.status(500).json({ message: 'Registration failed.' });
        }
    });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, userId: user.id, username: user.username, avatar: user.avatar });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.get('/api/profile/:userId', async (req, res) => {
    try {
        const userId = parseInt(req.params.userId, 10);
        const user = await dbGet('SELECT id, username, avatar, status FROM users WHERE id = ?', [userId]);
        if (!user) return res.status(404).json({ message: 'User not found.' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error.' });
    }
});

app.post('/api/update_profile', (req, res) => {
    upload(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ message: 'Avatar upload error: ' + err.message });
        } else if (err) {
            return res.status(400).json({ message: 'Error: ' + err.message });
        }

        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(401).json({ message: 'Authentication required.' });
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const userId = decoded.userId;
            const { newUsername } = req.body; 
            
            let updates = [];
            let params = [];
            let usernameChanged = false;
            let newAvatarPath = null;
            
            // 1. Username Update
            if (newUsername && newUsername !== decoded.username) {
                 const existing = await dbGet('SELECT id FROM users WHERE username = ? AND id != ?', [newUsername, userId]);
                 if (existing) {
                    if (req.file) fs.unlinkSync(req.file.path);
                    return res.status(400).json({ message: 'This username is already taken.' });
                 }
                 updates.push('username = ?');
                 params.push(newUsername);
                 usernameChanged = true;
            }

            // 2. Avatar Update
            if (req.file) {
                newAvatarPath = '/uploads/' + req.file.filename;
                updates.push('avatar = ?');
                params.push(newAvatarPath);
                
                const oldUser = await dbGet('SELECT avatar FROM users WHERE id = ?', [userId]);
                if (oldUser.avatar && oldUser.avatar.startsWith('/uploads/')) {
                    const oldPath = path.join(__dirname, 'public', oldUser.avatar);
                    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
                }
            }


            if (updates.length > 0) {
                params.push(userId);
                await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
                
                let responseData = { message: 'Profile updated. Please refresh the page.' };
                
                if (usernameChanged) {
                    const newToken = jwt.sign({ userId: userId, username: newUsername }, JWT_SECRET, { expiresIn: '1d' });
                    responseData.username = newUsername;
                    responseData.token = newToken;
                }
                if (newAvatarPath) {
                    responseData.avatar = newAvatarPath;
                }
                
                io.emit('userUpdateInfo', { userId: userId, newUsername: newUsername, newAvatar: newAvatarPath });

                return res.json(responseData);
            }

            res.status(400).json({ message: 'No data to update.' });

        } catch (error) {
            if (req.file) fs.unlinkSync(req.file.path);
            res.status(401).json({ message: 'Invalid token.' });
        }
    });
});


// --- SOCKET.IO LOGIC ---

const getDmChannels = async (userId) => {
    const dms = await dbAll(`
        SELECT 
            dc.id as channelId,
            u.id as userId,
            u.username,
            u.avatar
        FROM dm_channels dc
        JOIN users u ON u.id = CASE WHEN dc.user1_id = ? THEN dc.user2_id ELSE dc.user1_id END
        WHERE dc.user1_id = ? OR dc.user2_id = ?
    `, [userId, userId, userId]);

    return dms.reduce((acc, dm) => {
        acc[dm.userId] = { channelId: dm.channelId, username: dm.username, avatar: dm.avatar };
        return acc;
    }, {});
};

const loadChatHistory = async (chatId, isDM) => {
    const history = await dbAll('SELECT user_id, username, content, timestamp, avatar FROM messages WHERE channel_id = ? AND is_dm = ? ORDER BY timestamp ASC LIMIT 50', [chatId, isDM ? 1 : 0]);
    return history;
};

io.on('connection', (socket) => {
    let currentUserId = null; 
    let currentUsername = null;
    let currentAvatar = null;
    let currentChatId = 1; 
    let isChatDM = false;

    socket.on('authenticate', async (token) => {
        if (!token) return socket.disconnect();

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            currentUserId = decoded.userId;
            currentUsername = decoded.username;
            
            // --- SERVER CONSOLE LOGGING ---
            console.log(`[USER CONNECT] User authenticated: ID ${currentUserId} | Username: ${currentUsername} | Socket: ${socket.id}`);
            // ------------------------------
            
            const user = await dbGet('SELECT avatar, current_chat_id, is_dm_active FROM users WHERE id = ?', [currentUserId]);
            currentAvatar = user.avatar;
            currentChatId = user.current_chat_id || 1;
            isChatDM = user.is_dm_active == 1;
            
            if (userSocketMap[currentUserId] && userSocketMap[currentUserId] !== socket.id) {
                 io.sockets.sockets.get(userSocketMap[currentUserId])?.disconnect(true);
            }
            userSocketMap[currentUserId] = socket.id;
            
            await dbRun('UPDATE users SET status = ? WHERE id = ?', ['online', currentUserId]);
            
            const history = await loadChatHistory(currentChatId, isChatDM);
            socket.emit('messageHistory', history);

            const channels = await dbAll('SELECT id, name FROM channels ORDER BY name ASC');
            const dms = await getDmChannels(currentUserId);
            
            const roomName = `chat-${currentChatId}-${isChatDM ? 'dm' : 'channel'}`;
            socket.join(roomName);
            
            socket.emit('initialChannels', { 
                channels: channels, 
                dms: dms,
                activeChatId: currentChatId,
                isDM: isChatDM
            });
            
            io.emit('userStatusUpdate', { userId: currentUserId, username: currentUsername, status: 'online' });
            
        } catch (err) {
            console.error(`Socket authentication failed: ${err.message}.`);
            socket.disconnect(); 
        }
    });
    
    socket.on('joinChat', async (data) => {
        if (!currentUserId) return;
        
        const { newId, isDM } = data;
        const chatType = isDM ? 'dm' : 'channel';
        const newChatId = parseInt(newId, 10);

        socket.leave(`chat-${currentChatId}-${isChatDM ? 'dm' : 'channel'}`);
        
        currentChatId = newChatId;
        isChatDM = isDM;
        
        socket.join(`chat-${currentChatId}-${chatType}`);
        
        await dbRun('UPDATE users SET current_chat_id = ?, is_dm_active = ? WHERE id = ?', [currentChatId, isDM ? 1 : 0, currentUserId]);
        
        const history = await loadChatHistory(currentChatId, isChatDM);
        socket.emit('messageHistory', history);
        socket.emit('chatChanged', { newId: currentChatId, isDM: isChatDM });
    });
    
    socket.on('createChannel', async (channelName) => {
        if (!currentUserId || channelName.trim() === '') return socket.emit('requestError', 'Channel name cannot be empty.');
        
        const cleanName = channelName.toLowerCase().replace(/\s+/g, '-');
        try {
            const result = await dbRun('INSERT INTO channels (name) VALUES (?)', [cleanName]);
            
            io.emit('newChannelCreated', { id: result.lastID, name: cleanName });
            socket.emit('requestSuccess', `Channel #${cleanName} created.`);
        } catch (error) {
             socket.emit('requestError', 'A channel with this name already exists.');
        }
    });

    socket.on('startDM', async (recipientUsername) => {
        if (!currentUserId || recipientUsername.trim() === '') return socket.emit('requestError', 'Username cannot be empty.');

        const recipient = await dbGet('SELECT id, username, avatar FROM users WHERE username = ?', [recipientUsername]);
        if (!recipient) return socket.emit('requestError', 'User not found.');
        if (recipient.id === currentUserId) return socket.emit('requestError', 'Cannot start a DM with yourself.');

        const user1_id = Math.min(currentUserId, recipient.id);
        const user2_id = Math.max(currentUserId, recipient.id);

        let dmChannel = await dbGet('SELECT id FROM dm_channels WHERE user1_id = ? AND user2_id = ?', [user1_id, user2_id]);

        if (!dmChannel) {
            const result = await dbRun('INSERT INTO dm_channels (user1_id, user2_id) VALUES (?, ?)', [user1_id, user2_id]);
            dmChannel = { id: result.lastID };
        }
        
        const dmInfoForSender = { 
            channelId: dmChannel.id, 
            userId: recipient.id, 
            username: recipient.username, 
            avatar: recipient.avatar 
        };
        const dmInfoForRecipient = { 
            channelId: dmChannel.id, 
            userId: currentUserId, 
            username: currentUsername, 
            avatar: currentAvatar 
        };

        socket.emit('newDMStarted', dmInfoForSender);
        const recipientSocketId = userSocketMap[recipient.id];
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('newDMStarted', dmInfoForRecipient);
        }
        
        socket.emit('requestSuccess', `DM with ${recipient.username} started.`);
        socket.emit('joinChat', { newId: dmChannel.id, isDM: true });
    });

    socket.on('chat message', async (data) => {
        if (!currentUserId || !data.content || data.content.trim() === '') return; 
        
        const { content, isDM } = data;
        const dmFlag = isDM ? 1 : 0;
        const timestamp = new Date().toISOString();

        if (isDM) {
            const dmCheck = await dbGet('SELECT id FROM dm_channels WHERE id = ? AND (user1_id = ? OR user2_id = ?)', [currentChatId, currentUserId, currentUserId]);
            if (!dmCheck) return socket.emit('requestError', 'Error: You are not a member of this DM chat.');
        } else {
            const channelCheck = await dbGet('SELECT id FROM channels WHERE id = ?', [currentChatId]);
            if (!channelCheck) return socket.emit('requestError', 'Error: Channel does not exist.');
        }

        await dbRun('INSERT INTO messages (user_id, channel_id, username, content, timestamp, avatar, is_dm) VALUES (?, ?, ?, ?, ?, ?, ?)', 
            [currentUserId, currentChatId, currentUsername, content, timestamp, currentAvatar, dmFlag]);

        const messageData = {
            user_id: currentUserId, username: currentUsername, content: content, timestamp: timestamp, avatar: currentAvatar, channelId: currentChatId, isDM: isDM
        };
        
        const roomName = `chat-${currentChatId}-${isDM ? 'dm' : 'channel'}`;
        io.to(roomName).emit('newMessage', messageData); 
    });


    socket.on('disconnect', async () => {
        if (currentUserId) {
            console.log(`[USER DISCONNECT] User disconnected: ID ${currentUserId} | Username: ${currentUsername}`);
            delete userSocketMap[currentUserId];
            await dbRun('UPDATE users SET status = ? WHERE id = ?', ['offline', currentUserId]);
            io.emit('userStatusUpdate', { userId: currentUserId, username: currentUsername, status: 'offline' });
        }
    });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});