// routes/auth.routes.js (фрагмент)
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Регистрация
router.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // 1. Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 2. Создание пользователя
        const newUser = new User({ 
            username, 
            password: hashedPassword,
            // Аватар будет по умолчанию
        });
        await newUser.save();
        res.status(201).send({ message: 'Регистрация успешна.' });

    } catch (error) {
        // Ошибка, если имя пользователя уже занято
        res.status(500).send({ message: 'Ошибка регистрации.' });
    }
});

// Вход
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
        return res.status(400).send({ message: 'Пользователь не найден.' });
    }

    // Проверка пароля
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).send({ message: 'Неверный пароль.' });
    }

    // Генерация токена (для сессии)
    const token = jwt.sign(
        { userId: user._id, username: user.username }, 
        'CHAOS_SECRET_KEY', // В реальном приложении используйте переменную среды!
        { expiresIn: '1d' }
    );

    res.send({ token, userId: user._id, username: user.username });
});

module.exports = router;