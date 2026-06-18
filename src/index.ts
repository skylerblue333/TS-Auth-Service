import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const users: Record<string, any> = {}; // Mock DB

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (users[username]) {
        return res.status(400).json({ error: 'User exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    users[username] = { username, hash };
    res.status(201).json({ message: 'User created' });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (!user || !(await bcrypt.compare(password, user.hash))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

app.get('/verify', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, user: decoded });
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

if (require.main === module) {
    app.listen(3000, () => console.log('Auth service on port 3000'));
}

export default app;
