const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const mqtt = require('mqtt');
const cors = require('cors');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = 'super_secret_iot_key_123';

// Initialize Turso Cloud Database Client
const db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
});

async function ensureScheduleColumns() {
    const cols = await db.execute(`PRAGMA table_info(schedules)`);
    const existing = new Set(cols.rows.map((r) => r.name));

    if (!existing.has('system_id')) {
        await db.execute(`ALTER TABLE schedules ADD COLUMN system_id INTEGER`);
    }
    if (!existing.has('daily_time')) {
        await db.execute(`ALTER TABLE schedules ADD COLUMN daily_time TEXT`);
    }
    if (!existing.has('duration_sec')) {
        await db.execute(`ALTER TABLE schedules ADD COLUMN duration_sec INTEGER DEFAULT 0`);
    }
    if (!existing.has('last_triggered_date')) {
        await db.execute(`ALTER TABLE schedules ADD COLUMN last_triggered_date TEXT`);
    }
}

// Create tables asynchronously on startup with Systems & Projects support
async function initDB() {
    try {
        await db.execute(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            last_login TEXT DEFAULT 'Never'
        )`);

        // Systems / Projects table
        await db.execute(`CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            system_name TEXT,
            system_token TEXT UNIQUE,
            hardware_type TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);

        // PERSISTENT DEVICES TABLE
        await db.execute(`CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            system_id INTEGER,
            device_id TEXT,
            name TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(system_id) REFERENCES systems(id) ON DELETE CASCADE
        )`);

        await db.execute(`CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            system_id INTEGER,
            device_id TEXT,
            action TEXT,
            execute_at TEXT,
            daily_time TEXT,
            duration_sec INTEGER DEFAULT 0,
            last_triggered_date TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(system_id) REFERENCES systems(id) ON DELETE CASCADE
        )`);

        await ensureScheduleColumns();
        console.log('Connected to Turso DB successfully and initialized tables with systems support!');
    } catch (err) {
        console.error('Database initialization error:', err.message);
    }
}
initDB();

// Connect to MQTT Broker
const MQTT_BROKER = 'mqtt://broker.hivemq.com';
const mqttClient = mqtt.connect(MQTT_BROKER);

mqttClient.on('connect', () => {
    console.log('Connected to MQTT Broker');
    mqttClient.subscribe('myiot/+/state');
});

// Listen for messages from hardware (sensors & states)
mqttClient.on('message', (topic, message) => {
    const payload = message.toString();
    console.log(`MQTT [${topic}]: ${payload}`);

    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'STATE', topic, data: payload }));
        }
    });
});

// ================= REST API ROUTES =================

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.execute({
            sql: `INSERT INTO users (username, password, role) VALUES (?, ?, 'user')`,
            args: [username, hashedPassword]
        });
        res.json({ message: 'User registered successfully', userId: Number(result.lastInsertRowid) });
    } catch (err) {
        if (err.message && err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const rs = await db.execute({
            sql: `SELECT * FROM users WHERE username = ?`,
            args: [username]
        });
        const user = rs.rows[0];
        if (!user) return res.status(400).json({ error: 'Invalid username or password' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid username or password' });

        const currentTime = new Date().toLocaleString();
        await db.execute({
            sql: `UPDATE users SET last_login = ? WHERE id = ?`,
            args: [currentTime, user.id]
        });

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role || 'user' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        res.json({ message: 'Login successful', token, role: user.role || 'user' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// ================= ACCOUNT MANAGEMENT ROUTES =================

app.get('/api/account', verifyToken, async (req, res) => {
    try {
        const rs = await db.execute({
            sql: `SELECT id, username, role, last_login FROM users WHERE id = ?`,
            args: [req.user.id]
        });
        const user = rs.rows[0];
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.put('/api/account', verifyToken, async (req, res) => {
    const { username, current_password, new_password } = req.body;

    try {
        const rs = await db.execute({
            sql: `SELECT * FROM users WHERE id = ?`,
            args: [req.user.id]
        });
        const user = rs.rows[0];
        if (!user) return res.status(404).json({ error: 'User not found' });

        let updatedUsername = username ? username.trim() : user.username;
        let updatedPasswordHash = user.password;

        if (new_password) {
            if (!current_password) {
                return res.status(400).json({ error: 'Current password is required to set a new password.' });
            }
            const validPassword = await bcrypt.compare(current_password, user.password);
            if (!validPassword) {
                return res.status(400).json({ error: 'Current password is incorrect.' });
            }
            updatedPasswordHash = await bcrypt.hash(new_password, 10);
        }

        await db.execute({
            sql: `UPDATE users SET username = ?, password = ? WHERE id = ?`,
            args: [updatedUsername, updatedPasswordHash, req.user.id]
        });
        res.json({ message: 'Account updated successfully.' });
    } catch (err) {
        res.status(400).json({ error: 'Username already taken or database error.' });
    }
});

// ================= SYSTEM / PROJECT ROUTES =================

app.post('/api/systems', verifyToken, async (req, res) => {
    const { system_name, hardware_type } = req.body;
    if (!system_name) return res.status(400).json({ error: 'System name is required' });

    try {
        const system_token = crypto.randomBytes(16).toString('hex');
        const rs = await db.execute({
            sql: `INSERT INTO systems (user_id, system_name, system_token, hardware_type) VALUES (?, ?, ?, ?)`,
            args: [req.user.id, system_name, system_token, hardware_type || 'ESP32']
        });
        res.json({ message: 'System created successfully', system_token, id: Number(rs.lastInsertRowid) });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create system' });
    }
});

app.get('/api/systems', verifyToken, async (req, res) => {
    try {
        const rs = await db.execute({
            sql: `SELECT * FROM systems WHERE user_id = ?`,
            args: [req.user.id]
        });
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// ================= DEVICE PROVISIONING ROUTES =================

app.post('/api/devices', verifyToken, async (req, res) => {
    if (req.user.role === 'admin') {
        return res.status(403).json({ error: 'Administrators do not register personal devices.' });
    }
    const { system_id, device_id, name } = req.body;
    if (!system_id || !device_id || !name) return res.status(400).json({ error: 'System ID, Device ID, and name are required' });

    try {
        const sysCheck = await db.execute({
            sql: `SELECT * FROM systems WHERE id = ? AND user_id = ?`,
            args: [system_id, req.user.id]
        });
        if (sysCheck.rows.length === 0) {
            return res.status(403).json({ error: 'System not found or access denied.' });
        }

        const checkRs = await db.execute({
            sql: `SELECT * FROM devices WHERE system_id = ? AND device_id = ?`,
            args: [system_id, device_id]
        });
        if (checkRs.rows.length > 0) {
            return res.status(400).json({ error: 'Device ID already registered in this system.' });
        }

        const insertRs = await db.execute({
            sql: `INSERT INTO devices (user_id, system_id, device_id, name) VALUES (?, ?, ?, ?)`,
            args: [req.user.id, system_id, device_id, name]
        });
        res.json({ message: 'Device added successfully to system', id: Number(insertRs.lastInsertRowid) });
    } catch (err) {
        res.status(500).json({ error: 'Database error while saving device' });
    }
});

app.get('/api/devices', verifyToken, async (req, res) => {
    const systemId = req.query.system_id;
    try {
        let sql = `SELECT devices.id, devices.system_id, devices.device_id, devices.name, systems.system_name, systems.system_token 
                   FROM devices 
                   JOIN systems ON devices.system_id = systems.id 
                   WHERE devices.user_id = ?`;
        const args = [req.user.id];

        if (systemId && systemId !== 'all') {
            sql += ` AND devices.system_id = ?`;
            args.push(systemId);
        }

        const rs = await db.execute({ sql, args });
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// DELETE DEVICE ROUTE
app.delete('/api/devices/:id', verifyToken, async (req, res) => {
    const deviceIdToDelete = req.params.id;

    try {
        if (req.user.role !== 'admin') {
            const check = await db.execute({
                sql: `SELECT devices.id FROM devices 
                      JOIN systems ON devices.system_id = systems.id 
                      WHERE devices.id = ? AND systems.user_id = ?`,
                args: [deviceIdToDelete, req.user.id]
            });
            if (check.rows.length === 0) {
                return res.status(403).json({ error: 'Device not found or access denied.' });
            }
        }

        await db.execute({
            sql: `DELETE FROM devices WHERE id = ?`,
            args: [deviceIdToDelete]
        });

        res.json({ message: 'Device deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete device.' });
    }
});

// ================= SCHEDULE / RECURRING DAILY TIMER ROUTES =================

app.post('/api/schedules', verifyToken, async (req, res) => {
    const { system_id, device_id, action, daily_time, duration_sec } = req.body;
    const parsedDuration = Number(duration_sec);

    if (!system_id || !device_id || !action || !daily_time || !/^\d{2}:\d{2}$/.test(daily_time)) {
        return res.status(400).json({ error: 'System, device, action, and valid daily time (HH:MM) are required.' });
    }
    if (!Number.isFinite(parsedDuration) || parsedDuration < 0) {
        return res.status(400).json({ error: 'Duration in seconds must be 0 or a positive number.' });
    }
    if (!['ON', 'OFF'].includes(action)) {
        return res.status(400).json({ error: 'Action must be ON or OFF.' });
    }

    try {
        let query = `SELECT * FROM devices WHERE system_id = ? AND device_id = ?`;
        let params = [system_id, device_id];
        if (req.user.role !== 'admin') {
            query = `SELECT * FROM devices WHERE user_id = ? AND system_id = ? AND device_id = ?`;
            params = [req.user.id, system_id, device_id];
        }

        const devRs = await db.execute({ sql: query, args: params });
        if (devRs.rows.length === 0) return res.status(403).json({ error: 'Device not found in the selected system or access denied' });

        const schedRs = await db.execute({
            sql: `INSERT INTO schedules (user_id, system_id, device_id, action, execute_at, daily_time, duration_sec, last_triggered_date) 
                  VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
            args: [req.user.id, system_id, device_id, action, daily_time, daily_time, Math.floor(parsedDuration)]
        });
        res.json({ message: 'Daily recurring timer created successfully', id: Number(schedRs.lastInsertRowid) });
    } catch (err) {
        res.status(500).json({ error: 'Failed to save schedule' });
    }
});

app.get('/api/schedules', verifyToken, async (req, res) => {
    const systemId = req.query.system_id;
    try {
        let query = `
            SELECT schedules.*, systems.system_name 
            FROM schedules 
            LEFT JOIN systems ON schedules.system_id = systems.id
        `;
        const params = [];
        const conditions = [];

        if (req.user.role !== 'admin') {
            conditions.push(`schedules.user_id = ?`);
            params.push(req.user.id);
        }
        if (systemId && systemId !== 'all') {
            conditions.push(`schedules.system_id = ?`);
            params.push(systemId);
        }

        if (conditions.length > 0) {
            query += ` WHERE ` + conditions.join(` AND `);
        }

        const rs = await db.execute({ sql: query, args: params });
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/schedules/:id', verifyToken, async (req, res) => {
    try {
        await db.execute({
            sql: `DELETE FROM schedules WHERE id = ?`,
            args: [req.params.id]
        });
        res.json({ message: 'Schedule removed' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete schedule' });
    }
});

// ================= ADMIN MANAGEMENT ROUTES =================

app.get('/api/admin/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    try {
        const rs = await db.execute(`SELECT id, username, role, last_login FROM users`);
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/admin/users/:id', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    const userIdToDelete = req.params.id;
    if (parseInt(userIdToDelete) === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own active admin account.' });
    }

    try {
        await db.execute({ sql: `DELETE FROM systems WHERE user_id = ?`, args: [userIdToDelete] });
        await db.execute({ sql: `DELETE FROM devices WHERE user_id = ?`, args: [userIdToDelete] });
        await db.execute({ sql: `DELETE FROM schedules WHERE user_id = ?`, args: [userIdToDelete] });
        await db.execute({ sql: `DELETE FROM users WHERE id = ?`, args: [userIdToDelete] });
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.get('/api/admin/monitor', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    try {
        const rs = await db.execute(`
            SELECT users.username, systems.id AS system_id, systems.system_name, devices.device_id, devices.name, systems.system_token 
            FROM devices 
            JOIN users ON users.id = devices.user_id
            JOIN systems ON systems.id = devices.system_id
        `);
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

function getLocalDateAndTime(date = new Date()) {
    const pad = (n) => String(n).padStart(2, '0');
    const today = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
    const hhmm = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
    return { today, hhmm };
}

// Background Worker to Check and Trigger Recurring Daily Schedules every 5 seconds
setInterval(async () => {
    const { today, hhmm } = getLocalDateAndTime();
    try {
        const rs = await db.execute(`SELECT * FROM schedules`);
        const rows = rs.rows;
        if (!rows || rows.length === 0) return;

        for (const sched of rows) {
            const targetTime = sched.daily_time || (sched.execute_at && sched.execute_at.slice(-5));
            if (!targetTime || targetTime !== hhmm) continue;
            if (sched.last_triggered_date === today) continue;

            const controlTopic = `myiot/${sched.device_id}/control`;
            const primaryAction = sched.action;
            const durationSec = Number(sched.duration_sec) || 0;

            await db.execute({
                sql: `UPDATE schedules SET last_triggered_date = ? WHERE id = ?`,
                args: [today, sched.id]
            });

            mqttClient.publish(controlTopic, primaryAction);
            console.log(`⏱️ Daily Timer [${targetTime}] -> ${sched.device_id}: ${primaryAction} (duration: ${durationSec}s)`);

            if (durationSec > 0) {
                const oppositeAction = primaryAction === 'ON' ? 'OFF' : 'ON';
                setTimeout(() => {
                    mqttClient.publish(controlTopic, oppositeAction);
                    console.log(`⏱️ Timer Duration Ended (${durationSec}s) -> ${sched.device_id}: ${oppositeAction}`);
                }, durationSec * 1000);
            }
        }
    } catch (err) {
        console.error('Background worker error:', err);
    }
}, 5000);

// ================= WEBSOCKET SERVER (System Token Auth) =================
wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        try {
            const msg = JSON.parse(message);
            if (msg.system_token && msg.device_id && msg.state) {
                db.execute({
                    sql: `SELECT * FROM systems WHERE system_token = ?`,
                    args: [msg.system_token]
                }).then(rs => {
                    const system = rs.rows[0];
                    if (!system) return ws.send(JSON.stringify({ error: 'Invalid System Auth Token' }));

                    const controlTopic = `myiot/${msg.device_id}/control`;
                    mqttClient.publish(controlTopic, msg.state);
                });
            }
        } catch (err) {}
    });
});

// Safe Express fallback routing
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});