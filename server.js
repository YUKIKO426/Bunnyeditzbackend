const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error(err));

const keySchema = new mongoose.Schema({
  key: String,
  used: { type: Boolean, default: false },
  ip: String,
  usageTimestamps: [Date],
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date
});

const Key = mongoose.model('Key', keySchema);

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
};

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign({ user: 'admin' }, process.env.JWT_SECRET);
    res.json({ token });
  } else {
    res.status(403).json({ error: 'Invalid password' });
  }
});

app.get('/api/keys', authMiddleware, async (req, res) => {
  const keys = await Key.find().sort({ createdAt: -1 });
  res.json(keys);
});

app.post('/api/generate', authMiddleware, async (req, res) => {
  const { bindIP } = req.body;
  const newKey = new Key({
    key: [...Array(32)].map(() => Math.random().toString(36)[2]).join(''),
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
    ip: bindIP || null
  });
  await newKey.save();
  res.json(newKey);
});

app.delete('/api/delete/:id', authMiddleware, async (req, res) => {
  await Key.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

app.post('/api/validate', async (req, res) => {
  const { key, clientIP } = req.body;
  const found = await Key.findOne({ key });
  if (!found) return res.status(404).json({ error: 'Key not found' });
  if (found.used) return res.status(403).json({ error: 'Key already used' });
  if (found.expiresAt && new Date() > found.expiresAt)
    return res.status(403).json({ error: 'Key expired' });
  if (found.ip && found.ip !== clientIP)
    return res.status(403).json({ error: 'IP mismatch' });

  found.used = true;
  found.usageTimestamps.push(new Date());
  found.ip = found.ip || clientIP;
  await found.save();
  res.json({ success: true });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));