const express = require('express');
const axios = require('axios');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const Database = require('./database');
const { generateUsername, generatePassword, escapeHtml } = require('./utils/generators');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database();

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

// Middleware
app.use(limiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB session store
app.use(session({
    secret: process.env.SESSION_SECRET || 'medusaxd-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/medusaxd',
        collectionName: 'sessions'
    }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Environment variables
const API_LOGIN = process.env.API_LOGIN || 'medusaxd';
const API_PASSWORD = process.env.API_PASSWORD || 'Vnfrew001';
const API_BASE_URL = 'https://www.mega-debrid.eu/api.php';
const SITE_URL = process.env.SITE_URL || 'https://your-app.onrender.com';

// Telegram Configuration
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const TELEGRAM_ENABLED = TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID;

// Authentication middlewares
const requireAuth = async (req, res, next) => {
    if (req.session.userId) {
        try {
            const user = await db.getUserById(req.session.userId);
            if (user && user.is_active) {
                req.user = user;
                next();
            } else {
                req.session.destroy();
                res.status(401).json({ error: 'Account disabled' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Authentication error' });
        }
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
};

const requireAdmin = async (req, res, next) => {
    if (req.session.userId) {
        try {
            const user = await db.getUserById(req.session.userId);
            if (user && user.role === 'admin') {
                req.user = user;
                next();
            } else {
                res.status(403).json({ error: 'Admin access required' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Authorization error' });
        }
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
};

// Helper functions
function getUserIP(req) {
    return req.headers['x-forwarded-for'] || 
           req.headers['x-real-ip'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           'Unknown';
}

// Telegram notification functions
async function sendTelegramNotification(username, sourceLink, generatedLink, filename, userIP) {
    if (!TELEGRAM_ENABLED) return;

    try {
        const timestamp = new Date().toLocaleString('en-US', {
            timeZone: 'UTC',
            dateStyle: 'short',
            timeStyle: 'medium'
        });

        const sourceDomain = new URL(sourceLink).hostname.replace('www.', '');

        const message = `
🔗 <b>MedusaXD Link Generated</b>

👤 <b>User:</b> <code>${escapeHtml(username)}</code>
📅 <b>Time:</b> <i>${timestamp} UTC</i>
🌐 <b>Source:</b> <u>${escapeHtml(sourceDomain)}</u>
📁 <b>Filename:</b> <code>${escapeHtml(filename)}</code>
🔒 <b>IP Address:</b> <code>${escapeHtml(userIP)}</code>

<b>📎 Source Link:</b>
<pre>${escapeHtml(sourceLink)}</pre>

<b>⬇️ Generated Link:</b>
<pre>${escapeHtml(generatedLink)}</pre>

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Debrid Tracker</i>`;

        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_CHAT_ID,
            text: message,
            parse_mode: 'HTML',
            disable_web_page_preview: true
        });

        console.log('✅ Telegram notification sent');
    } catch (error) {
        console.error('❌ Telegram notification failed:', error.message);
    }
}

async function sendAdminNotification(username, telegramUsername) {
    if (!TELEGRAM_ENABLED) return;

    try {
        const message = `
🆕 <b>New User Registration</b>

👤 <b>Username:</b> <code>${escapeHtml(username)}</code>
📱 <b>Telegram:</b> @${escapeHtml(telegramUsername)}
📅 <b>Time:</b> <i>${new Date().toLocaleString()} UTC</i>
🎯 <b>Daily Limit:</b> 10 links

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Admin Alert</i>`;

        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_CHAT_ID,
            text: message,
            parse_mode: 'HTML'
        });
    } catch (error) {
        console.error('❌ Admin notification failed:', error.message);
    }
}

// Working getFreshToken function
async function getFreshToken() {
    try {
        const response = await axios.get(`${API_BASE_URL}?action=connectUser&login=${API_LOGIN}&password=${API_PASSWORD}`);

        if (response.data.response_code === 'ok') {
            return response.data.token;
        } else {
            throw new Error('Failed to get token');
        }
    } catch (error) {
        console.error('Token error:', error.message);
        throw error;
    }
}

// Telegram Bot Handler
async function handleTelegramUpdate(update) {
    if (!update.message || !update.message.text) return;

    const message = update.message;
    const chatId = message.chat.id;
    const userId = message.from.id;
    const text = message.text.trim();
    const chatType = message.chat.type;
    const telegramUsername = message.from.username || message.from.first_name || 'Unknown';

    // Handle group messages
    if (chatType !== 'private') {
        if (text.startsWith('/')) {
            await sendTelegramMessage(chatId, `
🤖 <b>MedusaXD Bot</b>

Please send me a private message to use bot commands.

<b>📱 Start Private Chat:</b>
Click here → @${process.env.BOT_USERNAME || 'your_bot_username'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Debrid Bot</i>`);
        }
        return;
    }

    try {
        switch (text) {
            case '/start':
                await handleStartCommand(chatId, telegramUsername);
                break;
            case '/register':
                await handleRegisterCommand(chatId, userId, telegramUsername);
                break;
            case '/resetpass':
                await handleResetPasswordCommand(chatId, userId);
                break;
            case '/myuser':
                await handleMyUserCommand(chatId, userId);
                break;
            case '/help':
                await handleHelpCommand(chatId);
                break;
            case '/status':
                await handleStatusCommand(chatId);
                break;
            default:
                if (text.startsWith('/')) {
                    await sendTelegramMessage(chatId, `
❓ <b>Unknown Command</b>

Use /help to see available commands.

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Bot</i>`);
                }
                break;
        }
    } catch (error) {
        console.error('Bot command error:', error);
        await sendTelegramMessage(chatId, `
❌ <b>Error</b>

Something went wrong. Please try again later.

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Bot</i>`);
    }
}

async function handleStartCommand(chatId, telegramUsername) {
    const message = `
👋 <b>Welcome to MedusaXD Bot!</b>

Hello <b>${escapeHtml(telegramUsername)}</b>! I can help you create an account for MedusaXD Debrid.

<b>🚀 Quick Start:</b>
• Send /register to create your account
• Get instant access to premium links
• 10 free generations daily

<b>📋 Available Commands:</b>
/register - Create new account
/myuser - Show account info
/resetpass - Reset password
/help - Command list

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 Ready to get started?</i>`;

    await sendTelegramMessage(chatId, message);
}

async function handleRegisterCommand(chatId, userId, telegramUsername) {
    try {
        // Check if user already exists
        const existingUser = await db.getUserByTelegramId(userId);

        if (existingUser) {
            const message = `
✅ <b>Already Registered</b>

You already have an account!

<b>🔑 Your Username:</b> <code>${escapeHtml(existingUser.username)}</code>
<b>🌐 Website:</b> <a href="${SITE_URL}">${SITE_URL}</a>
<b>🎯 Daily Limit:</b> ${existingUser.daily_limit} links

<b>💡 Need help?</b>
• /resetpass - Get new password
• /myuser - View account details

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 Welcome back!</i>`;

            await sendTelegramMessage(chatId, message);
            return;
        }

        // Generate new credentials
        let username, attempts = 0;
        do {
            username = generateUsername();
            attempts++;
            if (attempts > 10) throw new Error('Failed to generate unique username');
        } while (await db.getUserByUsername(username));

        const password = generatePassword();
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user in database
        const userData = {
            username,
            password_hash: hashedPassword,
            role: 'user',
            daily_limit: 10,
            is_active: true,
            telegram_user_id: userId.toString(),
            telegram_username: telegramUsername,
            telegram_chat_id: chatId.toString()
        };

        await db.createUser(userData);

        // Send credentials to user
        const message = `
🎉 <b>Account Created Successfully!</b>

<b>🔑 Your Login Credentials:</b>
• <b>Username:</b> <code>${username}</code>
• <b>Password:</b> <code>${password}</code>

<b>🌐 Website:</b> <a href="${SITE_URL}">${SITE_URL}</a>

<b>⚡ Account Details:</b>
• Daily Limit: 10 links
• Role: User
• Status: Active

<b>🔒 Security Notice:</b>
• This password is shown only once
• Use /resetpass to generate a new one
• Keep your credentials safe

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 Welcome to MedusaXD!</i>`;

        await sendTelegramMessage(chatId, message);

        // Send admin notification
        await sendAdminNotification(username, telegramUsername);

        console.log(`✅ New user registered: ${username} (Telegram: ${telegramUsername})`);

    } catch (error) {
        console.error('Registration error:', error);
        await sendTelegramMessage(chatId, `
❌ <b>Registration Failed</b>

Sorry, something went wrong during registration. Please try again later.

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Bot</i>`);
    }
}

async function handleResetPasswordCommand(chatId, userId) {
    try {
        const user = await db.getUserByTelegramId(userId);

        if (!user) {
            await sendTelegramMessage(chatId, `
❌ <b>Account Not Found</b>

You don't have a registered account yet.
Send /register to create one.

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Bot</i>`);
            return;
        }

        // Generate new password
        const newPassword = generatePassword();
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update in database
        await db.updateUser(user._id, { password_hash: hashedPassword });

        const message = `
🔄 <b>Password Reset Successful</b>

<b>🔑 Your New Credentials:</b>
• <b>Username:</b> <code>${escapeHtml(user.username)}</code>
• <b>New Password:</b> <code>${newPassword}</code>

<b>🌐 Website:</b> <a href="${SITE_URL}">${SITE_URL}</a>

<b>🔒 Security Notice:</b>
• This password is shown only once
• Your old password is now invalid
• Keep your credentials safe

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 Password Updated!</i>`;

        await sendTelegramMessage(chatId, message);

    } catch (error) {
        console.error('Password reset error:', error);
        await sendTelegramMessage(chatId, `
❌ <b>Reset Failed</b>

Sorry, couldn't reset your password. Please try again later.

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Bot</i>`);
    }
}

async function handleMyUserCommand(chatId, userId) {
    try {
        const user = await db.getUserByTelegramId(userId);

        if (!user) {
            await sendTelegramMessage(chatId, `
❌ <b>Account Not Found</b>

You don't have a registered account yet.
Send /register to create one.

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Bot</i>`);
            return;
        }

        const dailyUsage = await db.getDailyUsage(user._id);
        const remaining = user.daily_limit - dailyUsage;

        const message = `
👤 <b>Your Account Info</b>

<b>🔑 Account Details:</b>
• <b>Username:</b> <code>${escapeHtml(user.username)}</code>
• <b>Role:</b> ${user.role === 'admin' ? '👑 Admin' : '👤 User'}
• <b>Status:</b> ${user.is_active ? '✅ Active' : '❌ Disabled'}

<b>📊 Usage Today:</b>
• <b>Used:</b> ${dailyUsage} links
• <b>Limit:</b> ${user.daily_limit} links  
• <b>Remaining:</b> ${remaining} links

<b>🌐 Website:</b> <a href="${SITE_URL}">${SITE_URL}</a>

<b>💡 Commands:</b>
• /resetpass - New password
• /help - All commands

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Account</i>`;

        await sendTelegramMessage(chatId, message);

    } catch (error) {
        console.error('My user error:', error);
        await sendTelegramMessage(chatId, `
❌ <b>Error</b>

Couldn't fetch your account info. Please try again later.

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Bot</i>`);
    }
}

async function handleHelpCommand(chatId) {
    const message = `
🤖 <b>MedusaXD Bot Commands</b>

<b>📋 Account Management:</b>
/register - Create new account
/myuser - Show account info
/resetpass - Reset password

<b>ℹ️ Information:</b>
/help - Show this help
/status - Bot status

<b>🔔 Features:</b>
• Instant account creation
• Secure password generation  
• 10 free daily generations
• Premium link conversion

<b>🌐 Website:</b>
<a href="${SITE_URL}">${SITE_URL}</a>

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 Need help? Just ask!</i>`;

    await sendTelegramMessage(chatId, message);
}

async function handleStatusCommand(chatId) {
    const message = `
🟢 <b>MedusaXD Bot Status</b>

<b>📊 System Status:</b> <i>Online</i>
<b>🤖 Bot Status:</b> <i>Active</i>
<b>🌐 Website:</b> <i>Running</i>
<b>💾 Database:</b> <i>Connected</i>

<b>⚡ Services:</b>
• Account Registration
• Password Management
• Link Generation Tracking
• Real-time Notifications

<b>🌐 Website:</b>
<a href="${SITE_URL}">${SITE_URL}</a>

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 All systems operational!</i>`;

    await sendTelegramMessage(chatId, message);
}

async function sendTelegramMessage(chatId, text, options = {}) {
    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML',
            disable_web_page_preview: true,
            ...options
        });
    } catch (error) {
        console.error('Failed to send Telegram message:', error.message);
    }
}

// FIXED Authentication routes
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const user = await db.getUserByUsername(username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.is_active) {
            return res.status(401).json({ error: 'Account disabled' });
        }

        // FIXED: Use password_hash instead of password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // FIXED: Use _id instead of id
        req.session.userId = user._id;
        await db.updateLastLogin(user._id);

        res.json({
            success: true,
            user: {
                id: user._id,  // FIXED: Use _id
                username: user.username,
                role: user.role,
                daily_limit: user.daily_limit
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// User management routes (Admin only)
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await db.getAllUsers();
        const userStats = await db.getUserStats();

        const usersWithStats = users.map(user => {
            const stats = userStats.find(s => s._id.toString() === user._id.toString());
            return {
                ...user,
                total_generations: stats?.total_generations || 0,
                today_usage: stats?.today_usage || 0
            };
        });

        res.json(usersWithStats);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// FIXED admin user creation route
app.post('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const { username, password, email, role, daily_limit } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const existingUser = await db.getUserByUsername(username);
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // FIXED: Create user data without telegram fields for admin-created users
        const userData = {
            username,
            password_hash: hashedPassword,  // FIXED: Use password_hash
            email: email || undefined,
            role: role || 'user',
            daily_limit: daily_limit || 10,
            is_active: true
        };

        const userId = await db.createUser(userData);

        res.json({ success: true, userId });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = {};

        if (req.body.email !== undefined) updates.email = req.body.email;
        if (req.body.role !== undefined) updates.role = req.body.role;
        if (req.body.daily_limit !== undefined) updates.daily_limit = req.body.daily_limit;
        if (req.body.is_active !== undefined) updates.is_active = req.body.is_active;

        if (req.body.password) {
            updates.password_hash = await bcrypt.hash(req.body.password, 10);  // FIXED: Use password_hash
        }

        const changes = await db.updateUser(id, updates);

        if (changes === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const changes = await db.deleteUser(id);

        if (changes === 0) {
            return res.status(404).json({ error: 'User not found or cannot delete admin' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// History routes
app.get('/api/admin/history', requireAdmin, async (req, res) => {
    try {
        const history = await db.getAllHistory(200);
        const formattedHistory = history.map(item => ({
            ...item,
            username: item.user_id?.username || 'Unknown'
        }));
        res.json(formattedHistory);
    } catch (error) {
        console.error('Get history error:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

app.get('/api/user/history', requireAuth, async (req, res) => {
    try {
        const history = await db.getUserHistory(req.user._id);
        res.json(history);
    } catch (error) {
        console.error('Get user history error:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

// FIXED Main debrid functionality (using your working version)
app.post('/api/debrid', requireAuth, async (req, res) => {
    try {
        const { link } = req.body;
        const userIP = getUserIP(req);

        if (!link) {
            return res.status(400).json({ error: 'Link is required' });
        }

        // Check daily limit (FIXED: Use _id)
        const dailyUsage = await db.getDailyUsage(req.user._id);
        if (dailyUsage >= req.user.daily_limit) {
            return res.status(429).json({ 
                error: `Daily limit reached (${req.user.daily_limit} generations)` 
            });
        }

        // Validate URL format
        const urlPattern = /^https?:\/\/.+/;
        if (!urlPattern.test(link)) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        console.log('🔄 Processing debrid request for:', link);

        // Get fresh token (your working version)
        const token = await getFreshToken();
        console.log('✅ Got fresh token');

        // Make debrid request (your working version)
        const debridResponse = await axios.post(`${API_BASE_URL}?action=getLink&token=${token}`, 
            `link=${encodeURIComponent(link)}`,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        console.log('📡 Debrid API response:', debridResponse.data);

        if (debridResponse.data.response_code === 'ok') {
            const result = {
                success: true,
                downloadLink: debridResponse.data.debridLink,
                filename: debridResponse.data.filename
            };

            // Log to database (FIXED: Use _id)
            await db.addLinkHistory(
                req.user._id, 
                link, 
                result.downloadLink, 
                result.filename, 
                userIP
            );
            await db.updateDailyUsage(req.user._id);

            // Send Telegram notification (non-blocking)
            sendTelegramNotification(
                req.user.username,
                link, 
                result.downloadLink, 
                result.filename, 
                userIP
            ).catch(err => console.error('Telegram notification failed:', err));

            console.log('✅ Link generated successfully');
            res.json(result);
        } else {
            console.error('❌ Debrid API error:', debridResponse.data);
            res.status(400).json({ 
                error: 'Failed to process link. Please check if the link is valid and supported.' 
            });
        }

    } catch (error) {
        console.error('❌ Debrid error:', error);
        if (error.response) {
            console.error('API Response:', error.response.data);
        }
        res.status(500).json({ 
            error: 'Service temporarily unavailable. Please try again later.' 
        });
    }
});

// User status route (FIXED)
app.get('/api/user/status', requireAuth, async (req, res) => {
    try {
        const dailyUsage = await db.getDailyUsage(req.user._id);  // FIXED: Use _id
        res.json({
            user: {
                username: req.user.username,
                role: req.user.role,
                daily_limit: req.user.daily_limit,
                daily_usage: dailyUsage,
                remaining: req.user.daily_limit - dailyUsage
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get status' });
    }
});

// Telegram test endpoint
app.get('/api/test-telegram', requireAuth, async (req, res) => {
    if (!TELEGRAM_ENABLED) {
        return res.json({ 
            enabled: false, 
            error: 'Telegram not configured' 
        });
    }

    try {
        const testMessage = `
🧪 <b>MedusaXD Test Message</b>

<b>🤖 Bot Status:</b> <i>Online</i>
<b>📅 Test Time:</b> <code>${new Date().toLocaleString()}</code>
<b>🔧 System:</b> <u>MedusaXD Debrid Tracker</u>

<b>✅ Features Working:</b>
• <i>HTML Formatting</i>
• <i>Message Delivery</i>
• <i>API Connection</i>
• <i>User Registration</i>

━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 This is an automated test message.</i>`;

        const response = await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            {
                chat_id: TELEGRAM_CHAT_ID,
                text: testMessage,
                parse_mode: 'HTML',
                disable_web_page_preview: true
            }
        );

        if (response.data.ok) {
            res.json({ 
                enabled: true, 
                success: true,
                message: 'Test message sent successfully!',
                message_id: response.data.result.message_id
            });
        } else {
            res.status(500).json({ 
                enabled: true, 
                error: 'Failed to send message'
            });
        }

    } catch (error) {
        res.status(500).json({ 
            enabled: true, 
            error: 'Connection error: ' + error.message
        });
    }
});

// Telegram webhook endpoint
app.post('/webhook/telegram', async (req, res) => {
    if (!TELEGRAM_ENABLED) {
        return res.status(404).send('Telegram not configured');
    }

    try {
        await handleTelegramUpdate(req.body);
        res.status(200).send('OK');
    } catch (error) {
        console.error('Telegram webhook error:', error);
        res.status(500).send('Error');
    }
});

// Serve pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 MedusaXD Debrid server running on port ${PORT}`);
    console.log('📱 Telegram bot:', TELEGRAM_ENABLED ? 'enabled' : 'disabled');
    console.log('💾 Database: MongoDB Atlas');
    console.log('🌐 Site URL:', SITE_URL);
});
