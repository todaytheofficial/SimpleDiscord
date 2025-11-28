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
const JWT_SECRET = 'fdsfjsdklk$!#JH$@KLHJ$LASKDASJKFHdsnmfk'; // !!! CHANGE THIS IN PRODUCTION !!!

// --- Middleware and Setup ---

// Create folders for uploads and default images
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR);
}
// Serve uploaded files from /uploads route
app.use('/uploads', express.static(UPLOAD_DIR));

// 1. JSON Middleware: Must be before any routes that expect JSON (like /api/login)
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname))); 

// Multer storage configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        // Use user ID or a temp ID if not authenticated yet (for registration)
        const userId = req.user ? req.user.userId : 'temp_reg'; 
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
// Initial data for testing
let users = [
    { id: 1, username: 'testuser', password: 'password', avatar: '/img/anon_blue.png' }
];
let channels = []; 
let channelIdCounter = 1001; 
let messageIdCounter = 1;

let friendRequests = {}; 

let friends = {

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

// Function to create or retrieve a DM channel ID
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

    return channel;
}


// --- API Endpoints: Auth, Profile, and Settings ---

/** POST /api/register - Register a new user. 
 * NOTE: Multer handles the body parsing here, NOT express.json() */
app.post('/api/register', upload.single('avatar'), (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    if (getUserByUsername(username)) return res.status(400).json({ message: 'Username already taken' });

    const newUserId = users.length + 101;
    const newUser = {
        id: newUserId,
        username: username,
        password: password, 
        avatar: req.file ? `/uploads/${newUserId}_${path.parse(req.file.filename).base}` : '/img/anon_blue.png'
    };
    users.push(newUser);
    
    // Rename temp file if registration was successful
    if (req.file) {
        const oldPath = req.file.path;
        const newFilename = `${newUserId}_${path.parse(req.file.filename).base}`;
        const newPath = path.join(UPLOAD_DIR, newFilename);
        
        // This is important to ensure the file is saved with the correct, permanent ID
        fs.rename(oldPath, newPath, (err) => {
            if (err) console.error('Error renaming file:', err);
        });
        newUser.avatar = `/uploads/${newFilename}`;
    }

    res.status(201).json({ message: 'User registered successfully.' });
});

/** POST /api/login - Authenticate and return JWT. 
 * NOTE: This route uses express.json() middleware */
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = getUserByUsername(username);
    
    if (!user || user.password !== password) { 
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Fix: Generate a new token to ensure client's token is always valid
    const token = generateToken(user);
    
    // Initialize DM-channels for existing friends (important for old accounts)
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

/** POST /api/update-profile - Update username and/or avatar. 
 * NOTE: Requires verifyToken for auth, then Multer for body parsing */
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
        // Delete old avatar file if it's not a default image
        if (user.avatar && !user.avatar.startsWith('/img/')) { 
             try { fs.unlinkSync(path.join(__dirname, user.avatar)); } catch (e) { /* silent fail */ }
        }
        
        // Multer saved the new file with temp_reg ID, rename it to the actual userId
        const oldPath = req.file.path;
        const newFilename = `${userId}_${path.parse(req.file.filename).base}`;
        const newPath = path.join(UPLOAD_DIR, newFilename);
        
        fs.renameSync(oldPath, newPath); // Use Sync since this is inside a request handler

        user.avatar = `/uploads/${newFilename}`;
        updatedAvatar = user.avatar;
    }

    // Notify all clients about the profile change
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

    // Clean up all related data (friends, requests, DMs)
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
    
    // Delete avatar file
    if (deletedUser.avatar && !deletedUser.avatar.startsWith('/img/')) {
        try { fs.unlinkSync(path.join(__dirname, deletedUser.avatar)); } catch (e) { /* silent fail */ }
    }

    // Notify connected user and force logout
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
                
                // Load all friend data, including DM channel IDs
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
                
                // Load incoming pending requests
                const incomingRequests = Object.keys(friendRequests).filter(key => {
                    const requesterId = parseInt(key);
                    return friendRequests[requesterId] && friendRequests[requesterId][currentUser.id] === 'pending';
                }).map(requesterId => {
                    const requester = getUserById(parseInt(requesterId));
                    return {
                        userId: requester.id,
                        username: requester.username,
                        avatar: requester.avatar
                    };
                });
                
                // Select the first DM channel as the active one if none is set
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
            // Fix: Sends an explicit error for invalid/expired tokens
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
             // If recipient already sent a request, automatically accept it.
             
             // 1. Add as friends
             friends[currentUser.id] = friends[currentUser.id] || [];
             friends[recipient.id] = friends[recipient.id] || [];
             friends[currentUser.id].push(recipient.id);
             friends[recipient.id].push(currentUser.id);
             
             // 2. Create channel and delete request
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
             // Re-authenticate to refresh friend list for the sender
             socket.emit('authenticate', generateToken(currentUser)); 
             return;
        }
        
        // Save new request
        friendRequests[currentUser.id][recipient.id] = 'pending';
        socket.emit('requestSuccess', `Friend request sent to ${recipientUsername}.`);

        // Notify recipient if they are online
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
            
            // Re-authenticate to refresh friend list for the recipient
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