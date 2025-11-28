// models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String, default: 'default_chaos.png' }, // Аватар
    
    // Список друзей
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    
    // Список запросов
    friendRequests: [{
        senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        status: { type: String, enum: ['pending', 'accepted', 'ignored'], default: 'pending' }
    }],
    
    // Статус онлайн/оффлайн
    status: { type: String, enum: ['online', 'offline'], default: 'offline' }
});

module.exports = mongoose.model('User', UserSchema);