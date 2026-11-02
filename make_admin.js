const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./iot_platform.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
        return;
    }
    console.log('Connected to SQLite Database.');
});

const targetUsername = '123'; // Change to your username

db.serialize(() => {
    // Add the role column if it doesn't already exist
    db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`, (err) => {
        // Ignore error if the column already exists
    });

    // Update the user to admin
    db.run(`UPDATE users SET role = 'admin' WHERE username = ?`, [targetUsername], function(err) {
        if (err) {
            console.error('Error updating user role:', err.message);
        } else if (this.changes === 0) {
            console.log(`⚠️ No user found with the username "${targetUsername}".`);
        } else {
            console.log(`✅ Success! User "${targetUsername}" has been upgraded to admin.`);
        }
        db.close();
    });
});