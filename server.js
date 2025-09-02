const express = require('express');
const axios = require('axios');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const Database = require('./database');

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
app.use(session({
    secret: process.env.SESSION_SECRET || 'medusaxd-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Environment variables
const API_LOGIN = process.env.API_LOGIN || 'medusaxd';
const API_PASSWORD = process.env.API_PASSWORD || 'Vnfrew001';
const API_BASE_URL = 'https://www.mega-debrid.eu/api.php';

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

// Enhanced Telegram notification function with HTML formatting
async function sendTelegramNotification(username, sourceLink, generatedLink, filename, userIP) {
    if (!TELEGRAM_ENABLED) {
        console.log('🔸 Telegram not enabled - missing bot token or chat ID');
        return;
    }

    console.log('📱 Attempting to send Telegram notification...');
    console.log('📱 Bot Token:', TELEGRAM_BOT_TOKEN ? `${TELEGRAM_BOT_TOKEN.substring(0, 10)}...` : 'NOT SET');
    console.log('📱 Chat ID:', TELEGRAM_CHAT_ID);

    try {
        const timestamp = new Date().toLocaleString('en-US', {
            timeZone: 'UTC',
            dateStyle: 'short',
            timeStyle: 'medium'
        });

        const sourceDomain = new URL(sourceLink).hostname.replace('www.', '');

        // HTML formatted message for better appearance
        const message = `
🔗 <b>MedusaXD Link Generated</b>

👤 <b>User:</b> <code>${username}</code>
📅 <b>Time:</b> <i>${timestamp} UTC</i>
🌐 <b>Source:</b> <u>${sourceDomain}</u>
📁 <b>Filename:</b> <code>${filename}</code>
🔒 <b>IP Address:</b> <code>${userIP}</code>

<b>📎 Source Link:</b>
<pre>${sourceLink}</pre>

<b>⬇️ Generated Link:</b>
<pre>${generatedLink}</pre>

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🇵🇸 MedusaXD Debrid Tracker</i>`;

        console.log('📱 Sending HTML formatted message to Telegram API...');

        const telegramResponse = await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, 
            {
                chat_id: TELEGRAM_CHAT_ID,
                text: message,
                parse_mode: 'HTML',  // Changed from Markdown to HTML
                disable_web_page_preview: true
            },
            {
                timeout: 10000, // 10 second timeout
                headers: {
                    'Content-Type': 'application/json'
                }
            }
        );

        if (telegramResponse.data.ok) {
            console.log('✅ Telegram notification sent successfully');
            console.log('📱 Message ID:', telegramResponse.data.result.message_id);
        } else {
            console.error('❌ Telegram API returned error:', telegramResponse.data);
        }

    } catch (error) {
        console.error('❌ Failed to send Telegram notification:');
        console.error('📱 Error Type:', error.name);
        console.error('📱 Error Message:', error.message);

        if (error.response) {
            console.error('📱 Response Status:', error.response.status);
            console.error('📱 Response Data:', error.response.data);
        } else if (error.request) {
            console.error('📱 No response received:', error.request);
        }

        // Don't throw error - we don't want to break the main functionality
    }
}

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

// Authentication routes
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

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        req.session.userId = user.id;
        await db.updateLastLogin(user.id);

        res.json({
            success: true,
            user: {
                id: user.id,
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
            const stats = userStats.find(s => s.id === user.id);
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

        const userId = await db.createUser({
            username,
            password: hashedPassword,
            email,
            role: role || 'user',
            daily_limit: daily_limit || 10
        });

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
            updates.password = await bcrypt.hash(req.body.password, 10);
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
        res.json(history);
    } catch (error) {
        console.error('Get history error:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

app.get('/api/user/history', requireAuth, async (req, res) => {
    try {
        const history = await db.getUserHistory(req.user.id);
        res.json(history);
    } catch (error) {
        console.error('Get user history error:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

// Enhanced Telegram test endpoint with HTML formatting
app.get('/api/test-telegram', requireAuth, async (req, res) => {
    console.log('🧪 Testing Telegram configuration...');

    // Check environment variables
    if (!TELEGRAM_BOT_TOKEN) {
        return res.json({ 
            enabled: false, 
            error: 'TELEGRAM_BOT_TOKEN environment variable not set' 
        });
    }

    if (!TELEGRAM_CHAT_ID) {
        return res.json({ 
            enabled: false, 
            error: 'TELEGRAM_CHAT_ID environment variable not set' 
        });
    }

    try {
        console.log('🧪 Step 1: Testing bot info...');

        // Test 1: Get bot info
        const botInfoResponse = await axios.get(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe`,
            { timeout: 10000 }
        );

        if (!botInfoResponse.data.ok) {
            return res.status(500).json({ 
                enabled: true, 
                error: 'Invalid bot token: ' + JSON.stringify(botInfoResponse.data)
            });
        }

        console.log('✅ Bot info retrieved:', botInfoResponse.data.result.username);

        console.log('🧪 Step 2: Testing message send...');

        // Test 2: Send HTML formatted test message
        const testMessage = `
🧪 <b>MedusaXD Test Message</b>

<b>🤖 Bot Status:</b> <i>Online</i>
<b>📅 Test Time:</b> <code>${new Date().toLocaleString()}</code>
<b>🔧 System:</b> <u>MedusaXD Debrid Tracker</u>

<b>✅ Features Working:</b>
• <i>HTML Formatting</i>
• <i>Message Delivery</i>
• <i>API Connection</i>

<b>📊 Test Results:</b>
<pre>Connection: ✅ Success
Formatting: ✅ Success  
Delivery:   ✅ Success</pre>

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>This is an automated test message.</i>`;

        const messageResponse = await axios.post(
            `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            {
                chat_id: TELEGRAM_CHAT_ID,
                text: testMessage,
                parse_mode: 'HTML',
                disable_web_page_preview: true
            },
            {
                timeout: 10000,
                headers: {
                    'Content-Type': 'application/json'
                }
            }
        );

        if (messageResponse.data.ok) {
            console.log('✅ Test message sent successfully');
            res.json({ 
                enabled: true, 
                success: true,
                message: 'HTML formatted test message sent successfully!',
                bot_username: botInfoResponse.data.result.username,
                message_id: messageResponse.data.result.message_id
            });
        } else {
            console.error('❌ Message send failed:', messageResponse.data);
            res.status(500).json({ 
                enabled: true, 
                error: 'Failed to send message: ' + JSON.stringify(messageResponse.data)
            });
        }

    } catch (error) {
        console.error('❌ Telegram test failed:', error.message);

        let errorMessage = 'Connection error: ' + error.message;

        if (error.response) {
            errorMessage = `HTTP ${error.response.status}: ${JSON.stringify(error.response.data)}`;
        } else if (error.code === 'ECONNABORTED') {
            errorMessage = 'Request timeout - Telegram API not responding';
        }

        res.status(500).json({ 
            enabled: true, 
            error: errorMessage
        });
    }
});

// Main debrid functionality
app.post('/api/debrid', requireAuth, async (req, res) => {
    try {
        const { link } = req.body;
        const userIP = getUserIP(req);

        if (!link) {
            return res.status(400).json({ error: 'Link is required' });
        }

        // Check daily limit
        const dailyUsage = await db.getDailyUsage(req.user.id);
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

        // Get fresh token
        const token = await getFreshToken();

        // Make debrid request
        const debridResponse = await axios.post(`${API_BASE_URL}?action=getLink&token=${token}`, 
            `link=${encodeURIComponent(link)}`,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        if (debridResponse.data.response_code === 'ok') {
            const result = {
                success: true,
                downloadLink: debridResponse.data.debridLink,
                filename: debridResponse.data.filename
            };

            // Log to database
            await db.addLinkHistory(
                req.user.id, 
                link, 
                result.downloadLink, 
                result.filename, 
                userIP
            );
            await db.updateDailyUsage(req.user.id);

            // Send Telegram notification
            sendTelegramNotification(
                req.user.username,
                link, 
                result.downloadLink, 
                result.filename, 
                userIP
            ).catch(err => console.error('Telegram notification failed:', err));

            res.json(result);
        } else {
            res.status(400).json({ 
                error: 'Failed to process link. Please check if the link is valid and supported.' 
            });
        }

    } catch (error) {
        console.error('Debrid error:', error.message);
        res.status(500).json({ 
            error: 'Service temporarily unavailable. Please try again later.' 
        });
    }
});

// User status route
app.get('/api/user/status', requireAuth, async (req, res) => {
    try {
        const dailyUsage = await db.getDailyUsage(req.user.id);
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

// Telegram webhook endpoint with HTML formatting
app.post('/webhook/telegram', async (req, res) => {
    if (!TELEGRAM_ENABLED) {
        return res.status(404).send('Telegram not configured');
    }

    try {
        const update = req.body;

        if (update.message && update.message.text) {
            const chatId = update.message.chat.id;
            const text = update.message.text;

            // Only respond to the configured chat ID
            if (chatId.toString() === TELEGRAM_CHAT_ID) {
                if (text === '/status') {
                    const statusMessage = `
🟢 <b>🇵🇸MedusaXD Tracker Status</b>

<b>📊 System Status:</b> <i>Online</i>
<b>🤖 Bot Status:</b> <i>Active</i>
<b>📡 Monitoring:</b> <i>All link generations</i>

<b>⚡ Services:</b>
• Link Generation Tracking
• User Activity Monitoring  
• Real-time Notifications

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>🐍 MedusaXD Debrid Tracker</i>`;

                    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                        chat_id: chatId,
                        text: statusMessage,
                        parse_mode: 'HTML'
                    });
                } else if (text === '/help') {
                    const helpMessage = `
🤖 <b>MedusaXD Tracker Bot</b>

<b>📋 Available Commands:</b>
<code>/status</code> - Check tracker status
<code>/help</code> - Show this help menu

<b>🔔 Automatic Notifications:</b>
• <i>New link generations</i>
• <i>User activity tracking</i>  
• <i>Source domain monitoring</i>
• <i>IP address logging</i>

<b>📊 Tracked Information:</b>
• Username and timestamp
• Source and generated links
• File names and user IPs
• Daily usage statistics

━━━━━━━━━━━━━━━━━━━━━━━━━━━
<i>This bot automatically monitors all MedusaXD activity.</i>`;

                    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                        chat_id: chatId,
                        text: helpMessage,
                        parse_mode: 'HTML'
                    });
                }
            }
        }

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
    console.log('📱 Telegram tracking:', TELEGRAM_ENABLED ? 'enabled' : 'disabled');
    if (TELEGRAM_ENABLED) {
        console.log('📱 Bot Token:', TELEGRAM_BOT_TOKEN.substring(0, 10) + '...');
        console.log('📱 Chat ID:', TELEGRAM_CHAT_ID);
    }
});
