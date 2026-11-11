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

        // Systems / Projects table (Blynk-style template tokens)
        await db.execute(`CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            system_name TEXT,
            system_token TEXT UNIQUE,
            hardware_type TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);

        // PERSISTENT DEVICES TABLE (No DROP TABLE)
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
            device_id TEXT,
            action TEXT,
            execute_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);
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
        // Verify system ownership
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
    try {
        const rs = await db.execute({
            sql: `SELECT devices.id, devices.system_id, devices.device_id, devices.name, systems.system_name, systems.system_token 
                  FROM devices 
                  JOIN systems ON devices.system_id = systems.id 
                  WHERE devices.user_id = ?`,
            args: [req.user.id]
        });
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// ================= SCHEDULE / TIMER ROUTES =================

app.post('/api/schedules', verifyToken, async (req, res) => {
    const { device_id, action, execute_at } = req.body;
    if (!device_id || !action || !execute_at) return res.status(400).json({ error: 'Missing schedule parameters' });

    try {
        let query = `SELECT * FROM devices WHERE device_id = ?`;
        let params = [device_id];
        if (req.user.role !== 'admin') {
            query = `SELECT * FROM devices WHERE user_id = ? AND device_id = ?`;
            params = [req.user.id, device_id];
        }

        const devRs = await db.execute({ sql: query, args: params });
        if (devRs.rows.length === 0) return res.status(403).json({ error: 'Device not found or access denied' });

        const schedRs = await db.execute({
            sql: `INSERT INTO schedules (user_id, device_id, action, execute_at) VALUES (?, ?, ?, ?)`,
            args: [req.user.id, device_id, action, execute_at]
        });
        res.json({ message: 'Schedule created successfully', id: Number(schedRs.lastInsertRowid) });
    } catch (err) {
        res.status(500).json({ error: 'Failed to save schedule' });
    }
});

app.get('/api/schedules', verifyToken, async (req, res) => {
    try {
        let query = `SELECT * FROM schedules`;
        let params = [];
        if (req.user.role !== 'admin') {
            query = `SELECT * FROM schedules WHERE user_id = ?`;
            params = [req.user.id];
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
            SELECT users.username, systems.system_name, devices.device_id, devices.name, systems.system_token 
            FROM devices 
            JOIN users ON users.id = devices.user_id
            JOIN systems ON systems.id = devices.system_id
        `);
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// Background Worker to Check and Trigger Schedules every 10 seconds
setInterval(async () => {
    const now = new Date().toISOString().slice(0, 16);
    try {
        const rs = await db.execute({
            sql: `SELECT * FROM schedules WHERE execute_at <= ?`,
            args: [now]
        });
        const rows = rs.rows;
        if (!rows || rows.length === 0) return;

        for (const sched of rows) {
            const controlTopic = `myiot/${sched.device_id}/control`;
            mqttClient.publish(controlTopic, sched.action);
            console.log(`⏱️ Automated Timer Triggered: Sent ${sched.action} to ${sched.device_id}`);

            await db.execute({
                sql: `DELETE FROM schedules WHERE id = ?`,
                args: [sched.id]
            });
        }
    } catch (err) {
        console.error('Background worker error:', err);
    }
}, 10000);

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