const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const mqtt = require('mqtt');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = 'super_secret_iot_key_123';

// Initialize SQLite Database
const db = new sqlite3.Database('./iot_platform.db', (err) => {
    if (err) console.error('Database opening error: ', err.message);
    else console.log('Connected to SQLite Database.');
});

// Create tables including schedules
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        last_login TEXT DEFAULT 'Never'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        device_id TEXT UNIQUE,
        name TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        device_id TEXT,
        action TEXT,
        execute_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
});

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
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'user')`, [username, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: 'Username already exists' });
            res.json({ message: 'User registered successfully', userId: this.lastID });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid username or password' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid username or password' });

        const currentTime = new Date().toLocaleString();
        db.run(`UPDATE users SET last_login = ? WHERE id = ?`, [currentTime, user.id]);

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role || 'user' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        res.json({ message: 'Login successful', token, role: user.role || 'user' });
    });
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

// Device Provisioning
app.post('/api/devices', verifyToken, (req, res) => {
    if (req.user.role === 'admin') {
        return res.status(403).json({ error: 'Administrators do not register personal devices.' });
    }
    const { device_id, name } = req.body;
    db.run(`INSERT INTO devices (user_id, device_id, name) VALUES (?, ?, ?)`, [req.user.id, device_id, name], function(err) {
        if (err) return res.status(400).json({ error: 'Device ID already registered' });
        res.json({ message: 'Device added successfully', id: this.lastID });
    });
});

app.get('/api/devices', verifyToken, (req, res) => {
    db.all(`SELECT device_id, name FROM devices WHERE user_id = ?`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

// ================= SCHEDULE / TIMER ROUTES =================

app.post('/api/schedules', verifyToken, (req, res) => {
    const { device_id, action, execute_at } = req.body;
    if (!device_id || !action || !execute_at) return res.status(400).json({ error: 'Missing schedule parameters' });

    // Verify ownership or admin access
    let query = `SELECT * FROM devices WHERE device_id = ?`;
    let params = [device_id];
    if (req.user.role !== 'admin') {
        query = `SELECT * FROM devices WHERE user_id = ? AND device_id = ?`;
        params = [req.user.id, device_id];
    }

    db.get(query, params, (err, device) => {
        if (err || !device) return res.status(403).json({ error: 'Device not found or access denied' });

        db.run(`INSERT INTO schedules (user_id, device_id, action, execute_at) VALUES (?, ?, ?, ?)`, 
            [req.user.id, device_id, action, execute_at], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to save schedule' });
            res.json({ message: 'Schedule created successfully', id: this.lastID });
        });
    });
});

app.get('/api/schedules', verifyToken, (req, res) => {
    let query = `SELECT * FROM schedules`;
    let params = [];
    if (req.user.role !== 'admin') {
        query = `SELECT * FROM schedules WHERE user_id = ?`;
        params = [req.user.id];
    }
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.delete('/api/schedules/:id', verifyToken, (req, res) => {
    db.run(`DELETE FROM schedules WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to delete schedule' });
        res.json({ message: 'Schedule removed' });
    });
});

// ================= ADMIN MANAGEMENT ROUTES =================

app.get('/api/admin/users', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    db.all(`SELECT id, username, role, last_login FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.delete('/api/admin/users/:id', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    const userIdToDelete = req.params.id;
    if (parseInt(userIdToDelete) === req.user.id) {
        return res.status(400).json({ error: 'Cannot delete your own active admin account.' });
    }

    db.serialize(() => {
        db.run(`DELETE FROM devices WHERE user_id = ?`, [userIdToDelete]);
        db.run(`DELETE FROM schedules WHERE user_id = ?`, [userIdToDelete]);
        db.run(`DELETE FROM users WHERE id = ?`, [userIdToDelete], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to delete user' });
            res.json({ message: 'User deleted successfully' });
        });
    });
});

app.get('/api/admin/monitor', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied.' });
    db.all(`
        SELECT users.username, devices.device_id, devices.name 
        FROM devices 
        JOIN users ON users.id = devices.user_id
    `, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

// Background Worker to Check and Trigger Schedules every 10 seconds
setInterval(() => {
    const now = new Date().toISOString().slice(0, 16); // Format matches HTML datetime-local: YYYY-MM-DDTHH:mm
    db.all(`SELECT * FROM schedules WHERE execute_at <= ?`, [now], (err, rows) => {
        if (err || !rows) return;

        rows.forEach(sched => {
            const controlTopic = `myiot/${sched.device_id}/control`;
            mqttClient.publish(controlTopic, sched.action);
            console.log(`⏱️ Automated Timer Triggered: Sent ${sched.action} to ${sched.device_id}`);

            // Remove executed schedule once triggered
            db.run(`DELETE FROM schedules WHERE id = ?`, [sched.id]);
        });
    });
}, 10000);

// ================= WEBSOCKET SERVER =================
wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        try {
            const msg = JSON.parse(message);
            if (msg.token && msg.device_id && msg.state) {
                jwt.verify(msg.token, JWT_SECRET, (err, user) => {
                    if (err) return;

                    let query = `SELECT * FROM devices WHERE device_id = ?`;
                    let params = [msg.device_id];

                    if (user.role !== 'admin') {
                        query = `SELECT * FROM devices WHERE user_id = ? AND device_id = ?`;
                        params = [user.id, msg.device_id];
                    }

                    db.get(query, params, (err, device) => {
                        if (err || !device) return ws.send(JSON.stringify({ error: 'Access denied' }));

                        const controlTopic = `myiot/${msg.device_id}/control`;
                        mqttClient.publish(controlTopic, msg.state);
                    });
                });
            }
        } catch (err) {}
    });
});

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});