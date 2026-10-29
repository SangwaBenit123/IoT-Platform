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

const JWT_SECRET = 'super_secret_iot_key_123'; // In production, put this in an environment variable

// 1. Initialize SQLite Database
const db = new sqlite3.Database('./iot_platform.db', (err) => {
    if (err) console.error('Database opening error: ', err.message);
    else console.log('Connected to SQLite Database.');
});

// Create Users and Devices tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        device_id TEXT UNIQUE,
        name TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

// 2. Connect to MQTT Broker
const MQTT_BROKER = 'mqtt://broker.hivemq.com';
const mqttClient = mqtt.connect(MQTT_BROKER);

mqttClient.on('connect', () => {
    console.log('Connected to MQTT Broker');
    // Subscribe to all device state topics wildcard
    mqttClient.subscribe('myiot/+/state');
});

// Listen for messages from hardware
mqttClient.on('message', (topic, message) => {
    const payload = message.toString();
    console.log(`MQTT [${topic}]: ${payload}`);

    // Broadcast to all connected WebSockets
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'STATE', topic, data: payload }));
        }
    });
});

// ================= REST API ROUTES (Auth & Devices) =================

// Register User
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: 'Username already exists' });
            res.json({ message: 'User registered successfully', userId: this.lastID });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login User
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid username or password' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid username or password' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ message: 'Login successful', token });
    });
});

// Middleware to authenticate JWT
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

// Register a New Device for Logged-in User
app.post('/api/devices', verifyToken, (req, res) => {
    const { device_id, name } = req.body;
    db.run(`INSERT INTO devices (user_id, device_id, name) VALUES (?, ?, ?)`, [req.user.id, device_id, name], function(err) {
        if (err) return res.status(400).json({ error: 'Device ID already registered' });
        res.json({ message: 'Device added successfully', id: this.lastID });
    });
});

// Get User's Devices
app.get('/api/devices', verifyToken, (req, res) => {
    db.all(`SELECT device_id, name FROM devices WHERE user_id = ?`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

// ================= WEBSOCKET SERVER (Multi-Tenant Secure Control) =================
wss.on('connection', (ws, req) => {
    console.log('Client connected to WebSocket');

    ws.on('message', (message) => {
        try {
            const msg = JSON.parse(message);
            
            // Expecting format: { token: 'JWT_TOKEN', device_id: 'device1', state: 'ON' }
            if (msg.token && msg.device_id && msg.state) {
                jwt.verify(msg.token, JWT_SECRET, (err, user) => {
                    if (err) return ws.send(JSON.stringify({ error: 'Unauthorized token' }));

                    // Verify that this user actually owns this device in the database
                    db.get(`SELECT * FROM devices WHERE user_id = ? AND device_id = ?`, [user.id, msg.device_id], (err, device) => {
                        if (err || !device) {
                            return ws.send(JSON.stringify({ error: 'Device not found or access denied' }));
                        }

                        // Authorized! Publish command to specific device control topic
                        const controlTopic = `myiot/${msg.device_id}/control`;
                        mqttClient.publish(controlTopic, msg.state);
                        console.log(`User ${user.username} sent ${msg.state} to ${msg.device_id}`);
                    });
                });
            }
        } catch (err) {
            console.error('Invalid WS message payload');
        }
    });
});

// Explicit fallback route to ensure index.html serves correctly for frontend routing/refreshes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Secure multi-tenant IoT server running on port ${PORT}`);
});