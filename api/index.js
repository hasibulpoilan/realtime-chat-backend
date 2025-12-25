const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');
const fs = require('fs');
const aiRoutes = require('./routes/ai');

dotenv.config();

const app = express();
app.use('/uploads', express.static(__dirname + '/uploads'));
app.use(bodyParser.json());
app.use(cookieParser());

const uploadsDir = __dirname + '/uploads';
if (!fs.existsSync(uploadsDir)) { 
    fs.mkdirSync(uploadsDir);
}

app.use(cors({
    origin: "*", 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
}));

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});
app.use('/api', aiRoutes);


const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

async function getUserDataFromRequest(req) {
    return new Promise((resolve, reject) => {
        const token = req.cookies?.token;
        if (token) {
            jwt.verify(token, JWT_SECRET, {}, (err, userData) => {
                if (err) { 
                    console.error('JWT verification error:', err);
                    return reject(err);
                }
                resolve(userData);
            });
        } else {
            console.error('No token found in request');
            reject('No token');
        }
    });
}

app.get('/test', (req, res) => {
    res.json('test ok');
});

app.get('/messages/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const userData = await getUserDataFromRequest(req);
        console.log("User Data:", userData);

        const ourUserId = userData.id;

        const messagesQuery = `
            SELECT * FROM messagess
            WHERE (sender = $1 AND recipient = $2) 
            OR (sender = $2 AND recipient = $1) 
            ORDER BY created_at ASC;
        `;
        const messages = await pool.query(messagesQuery, [userId, ourUserId]);
        res.json(messages.rows);
    } catch (err) {
        console.error('Error fetching messages:', err);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

app.get('/people', async (req, res) => {
    console.log("Fetching people...");
    try {
        const usersQuery = `SELECT id, username FROM users`;
        const result = await pool.query(usersQuery);
        res.json(result.rows);
        console.log(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/profile', (req, res) => {
    const token = req.cookies.token;
    if (token) {
        jwt.verify(token, JWT_SECRET, {}, (err, userData) => {
            if (err) {
                console.log('JWT Error:', err);
                return res.status(403).json('Invalid token');
            }
            res.json(userData);
        });
    } else {
        res.status(401).json('No token');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);

        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
        });

        res.status(201).json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
            },
            token
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to log in user' });
    }
});

app.post('/logout', (req, res) => {
    res.cookie('token', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
    }).json('ok');
});
app.delete('/messages/:id', async (req, res) => {
    const { id } = req.params;
    if (isNaN(id)) {
        return res.status(400).json({ success: false, message: 'Invalid message ID' });
    }
    try {
        const userData = await getUserDataFromRequest(req);
        const deleteQuery = `
            DELETE FROM messagess
            WHERE id = $1 AND (sender = $2 OR recipient = $2) -- User can delete messages they sent/received
            RETURNING *;
        `;
        const result = await pool.query(deleteQuery, [id, userData.id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'Message not found or permission denied' });
        }

        res.status(200).json({ success: true, message: 'Message deleted', deletedMessage: result.rows[0] });
    } catch (err) {
        console.error('Error deleting message:', err);
        res.status(500).json({ success: false, message: 'Failed to delete message' });
    }
});

app.delete('/users/:id', async (req, res) => {
    const { id } = req.params;
    if (isNaN(id)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const anonymizeMessagesQuery = `
            UPDATE messagess
            SET sender = NULL, recipient = NULL
            WHERE sender = $1 OR recipient = $1;
        `;
        await client.query(anonymizeMessagesQuery, [id]);
        const deleteUserQuery = `
            DELETE FROM users
            WHERE id = $1
            RETURNING *;
        `;
        const result = await client.query(deleteUserQuery, [id]);

        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        await client.query('COMMIT');
        res.status(200).json({
            success: true,
            message: 'User deleted successfully',
            deletedUser: result.rows[0],
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error during delete operation:', err);
        res.status(500).json({ success: false, message: 'Failed to delete user' });
    } finally {
        client.release();
    }
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
            [username, hashedPassword]
        );

        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);

        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
        });

        res.status(201).json({
            message: 'User registered successfully',
            user,
            token
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

const server = app.listen(4000, () => {
    console.log('Server is running on port 4000');
});

const wss = new WebSocket.Server({ server });
async function saveMessage(sender, recipient, text, file) {
    const query = `
        INSERT INTO messagess (sender, recipient, text,file)
        VALUES ($1, $2, $3,$4)
        RETURNING *;
    `;
    const values = [sender, recipient, text, file];

    try {
        const res = await pool.query(query, values);
        console.log('Message saved:', res.rows[0]);
        return res.rows[0];
    } catch (err) {
        console.error('Error saving message:', err);
    }
}

wss.on('connection', (connection, req) => {

    function notifyAboutOnlinePeople() {
        wss.clients.forEach(client => {
            client.send(JSON.stringify({
                online: [...wss.clients].map(c => ({ userId: c.userId, username: c.username }))
            }));
        });
    }

    connection.isAlive = true;

    connection.timer = setInterval(() => {
        connection.ping();

        if (connection.deathTimer) {
            clearTimeout(connection.deathTimer);
        }
        connection.deathTimer = setTimeout(() => {
            if (!connection.isAlive) {
                clearInterval(connection.timer);
                connection.terminate();
                notifyAboutOnlinePeople();
                console.log('dead');
            }
        }, 1000);
    }, 5000);

    connection.on('pong', () => {
        connection.isAlive = true;
        clearTimeout(connection.deathTimer);
        console.log('pong');
    })

    connection.on('close', () => {
        clearInterval(connection.timer);
        clearTimeout(connection.deathTimer);
        notifyAboutOnlinePeople();
        console.log('Connection closed');
    });

    const cookies = req.headers.cookie;
    if (cookies) {
        const tokenCookieString = cookies.split(';').find(str => str.startsWith('token='));
        if (tokenCookieString) {
            const token = tokenCookieString.split('=')[1];
            if (token) {
                jwt.verify(token, JWT_SECRET, {}, (err, userData) => {
                    if (err) {
                        console.error('JWT verification failed:', err);
                        return connection.close();
                    }
                    const { id: userId, username } = userData;
                    connection.userId = userId;
                    connection.username = username;
                    console.log(`User connected: ${username}`);
                });
            }
        }
    }

    wss.clients.forEach(client => {
        client.send(JSON.stringify({
            online: [...wss.clients].map(c => ({ userId: c.userId, username: c.username }))
        }));
    });



    connection.on('message', async (message) => {
        const messageData = JSON.parse(message.toString());

        if (messageData.type === 'offer' || messageData.type === 'answer' || messageData.type === 'ice-candidate') {
            const recipientSocket = [...wss.clients].find(client => client.userId == messageData.recipient);

            if (recipientSocket) {
                recipientSocket.send(JSON.stringify(messageData));
            }
        }

        const { recipient, text, file } = messageData;
        let filename = null;

        if (file) {
            const parts = file.name.split('.');
            const ext = parts[parts.length - 1];
            filename = Date.now() + '.' + ext;
            const path = __dirname + '/uploads/' + filename;

            const bufferData = Buffer.from(file.data, 'base64');
            await fs.promises.writeFile(path, bufferData);
        }

        if (recipient && (text || file)) {
            await saveMessage(connection.userId, recipient, text, filename);
            [...wss.clients]
                .filter(c => c.userId == recipient)
                .forEach(c =>
                    c.send(
                        JSON.stringify({
                            text,
                            sender: connection.userId,
                            recipient,
                            file: file ? filename : null,
                            id: messageData.id,
                        })
                    )
                );
        }
    });

    notifyAboutOnlinePeople();

    connection.on('close', () => {
        console.log(`User disconnected: ${connection.username}`);
        const onlineUsers = [...wss.clients].map(c => ({
            userId: c.userId,
            username: c.username
        }));

        const allUsersQuery = `SELECT id, username FROM users`;
        pool.query(allUsersQuery).then(result => {
            const allUsers = result.rows;
            const offlinePeople = allUsers.filter(user => {
                return !onlineUsers.some(onlineUser => onlineUser.userId === user.id);
            });

            console.log('Offline people:', offlinePeople);

            wss.clients.forEach(client => {
                client.send(JSON.stringify({ offline: offlinePeople }));
            });
        }).catch(err => {
            console.error('Failed to retrieve all users:', err);
        });
    });
});

app.post('/api/ai-chat', async (req, res) => {
  const { message } = req.body;
  console.log("Message:", message);
  const GROQ_API_KEY = process.env.GROQ_API_KEY;

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: "meta-llama/llama-4-scout-17b-16e-instruct",
        messages: [
          {
            role: "user",
            content: message
          } 
        ]
      })
    });

    if (!response.ok) {
      const text = await response.text();
      console.error('Groq API error:', text);
      return res.status(500).json({ reply: "Groq model not available." });
    }

    const data = await response.json();
    const botReply = data.choices?.[0]?.message?.content || "No response from Groq AI.";

    res.json({ reply: botReply });

  } catch (err) {
    console.error("Groq API Error:", err);
    res.status(500).json({ reply: "Failed to get response from Groq." });
  }
});


