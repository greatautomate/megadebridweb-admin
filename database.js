const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

class Database {
    constructor() {
        const dbPath = process.env.NODE_ENV === 'production' 
            ? '/tmp/medusaxd.db' 
            : path.join(__dirname, 'medusaxd.db');

        this.db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error('Error opening database:', err.message);
            } else {
                console.log('✅ Connected to SQLite database');
                this.initTables();
            }
        });
    }

    initTables() {
        const userTable = `
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                daily_limit INTEGER DEFAULT 10,
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            )
        `;

        const linkHistoryTable = `
            CREATE TABLE IF NOT EXISTS link_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                source_link TEXT NOT NULL,
                generated_link TEXT NOT NULL,
                filename TEXT,
                user_ip TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `;

        const dailyUsageTable = `
            CREATE TABLE IF NOT EXISTS daily_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                usage_date DATE NOT NULL,
                generation_count INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, usage_date)
            )
        `;

        this.db.serialize(() => {
            this.db.run(userTable);
            this.db.run(linkHistoryTable);
            this.db.run(dailyUsageTable);
            this.createDefaultAdmin();
        });
    }

    async createDefaultAdmin() {
        // Check if the new admin exists
        const adminExists = await this.getUserByUsername('medusaxd');
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('aiyman123', 10);
            this.db.run(
                `INSERT INTO users (username, password, email, role, daily_limit) 
                 VALUES (?, ?, ?, ?, ?)`,
                ['medusaxd', hashedPassword, 'admin@medusaxd.com', 'admin', 999999],
                function(err) {
                    if (err) {
                        console.error('Error creating admin:', err.message);
                    } else {
                        console.log('✅ Default admin user created (medusaxd/aiyman123)');
                    }
                }
            );
        }

        // Clean up old admin account if it exists
        const oldAdmin = await this.getUserByUsername('admin');
        if (oldAdmin && oldAdmin.role === 'admin') {
            this.db.run('DELETE FROM users WHERE username = ?', ['admin'], (err) => {
                if (!err) {
                    console.log('🗑️ Old admin account removed');
                }
            });
        }
    }

    // User management methods
    getUserByUsername(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    getUserById(id) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE id = ?',
                [id],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    createUser(userData) {
        return new Promise((resolve, reject) => {
            const { username, password, email, role, daily_limit } = userData;
            this.db.run(
                `INSERT INTO users (username, password, email, role, daily_limit) 
                 VALUES (?, ?, ?, ?, ?)`,
                [username, password, email || null, role || 'user', daily_limit || 10],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    updateUser(id, userData) {
        return new Promise((resolve, reject) => {
            const fields = Object.keys(userData).map(key => `${key} = ?`).join(', ');
            const values = [...Object.values(userData), id];

            this.db.run(
                `UPDATE users SET ${fields} WHERE id = ?`,
                values,
                function(err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    deleteUser(id) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM users WHERE id = ? AND role != "admin"',
                [id],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    getAllUsers() {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT id, username, email, role, daily_limit, is_active, 
                        created_at, last_login FROM users ORDER BY created_at DESC`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    // Usage tracking methods
    addLinkHistory(userId, sourceLink, generatedLink, filename, userIP) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO link_history (user_id, source_link, generated_link, filename, user_ip) 
                 VALUES (?, ?, ?, ?, ?)`,
                [userId, sourceLink, generatedLink, filename, userIP],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    updateDailyUsage(userId) {
        return new Promise((resolve, reject) => {
            const today = new Date().toISOString().split('T')[0];
            this.db.run(
                `INSERT INTO daily_usage (user_id, usage_date, generation_count) 
                 VALUES (?, ?, 1) 
                 ON CONFLICT(user_id, usage_date) 
                 DO UPDATE SET generation_count = generation_count + 1`,
                [userId, today],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    getDailyUsage(userId) {
        return new Promise((resolve, reject) => {
            const today = new Date().toISOString().split('T')[0];
            this.db.get(
                'SELECT generation_count FROM daily_usage WHERE user_id = ? AND usage_date = ?',
                [userId, today],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row ? row.generation_count : 0);
                }
            );
        });
    }

    getUserHistory(userId, limit = 50) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT * FROM link_history 
                 WHERE user_id = ? 
                 ORDER BY created_at DESC 
                 LIMIT ?`,
                [userId, limit],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    getAllHistory(limit = 100) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT lh.*, u.username 
                 FROM link_history lh 
                 JOIN users u ON lh.user_id = u.id 
                 ORDER BY lh.created_at DESC 
                 LIMIT ?`,
                [limit],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    getUserStats() {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT u.id, u.username, u.daily_limit, u.is_active,
                        COUNT(lh.id) as total_generations,
                        COALESCE(du.generation_count, 0) as today_usage
                 FROM users u
                 LEFT JOIN link_history lh ON u.id = lh.user_id
                 LEFT JOIN daily_usage du ON u.id = du.user_id AND du.usage_date = DATE('now')
                 GROUP BY u.id
                 ORDER BY u.username`,
                [],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
    }

    updateLastLogin(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                [userId],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }
}

module.exports = Database;
