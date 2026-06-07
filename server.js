'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

app.use(helmet());

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORSポリシーによりブロックされました'));
    }
  },
  methods: ['GET', 'POST'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'リクエストが多すぎます。しばらく時間をおいてお試しください。' }
});
app.use('/api/', apiLimiter);

const RAW_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; 
const ADMIN_PASSWORD_HASH = crypto.createHash('sha256').update(RAW_PASSWORD).digest('hex');

const MAX_MESSAGES = 500;
let messages = [];
let activeConnections = 0;

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.get('/api/messages', (req, res) => {
  res.json(messages);
});

app.post('/api/messages', [
  body('username').trim().isLength({ min: 1, max: 24 }).escape(),
  body('message').trim().isLength({ min: 1, max: 1000 }).escape(),
  body('time').trim().isLength({ max: 50 }).escape(),
  body('seed').trim().isLength({ max: 64 }).escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: '入力値が不正、または不足しています。' });
  }

  const { username, message, time, seed } = req.body;

  const newPost = {
    id: crypto.randomUUID(),
    username,
    message,
    time,
    seed,
    reactions: {}
  };

  messages.push(newPost);
  
  if (messages.length > MAX_MESSAGES) {
    messages.shift();
  }

  io.emit('newMessage', newPost);
  res.status(201).json({ success: true, message: '投稿が完了しました。' });
});

app.post('/api/pass', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: 'パスワードを入力してください' });
  }

  const inputHash = crypto.createHash('sha256').update(password).digest('hex');
  
  const isMatch = crypto.timingSafeEqual(
    Buffer.from(inputHash, 'utf-8'),
    Buffer.from(ADMIN_PASSWORD_HASH, 'utf-8')
  );

  if (isMatch) {
    if (req.headers['x-requested-with'] === 'fetch') {
      messages = [];
      io.emit('clearMessages');
      return res.json({ message: '履歴を削除しました' });
    }
    return res.json({ message: '認証に成功しました' });
  } else {
    return res.status(401).json({ message: 'パスワードが一致しません' });
  }
});

app.get('/user', (req, res) => {
  res.json({ userCount: activeConnections });
});

const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket'],
  allowEIO3: false
});

io.on('connection', (socket) => {
  activeConnections++;
  io.emit('userCount', { userCount: activeConnections });

  socket.on('updateReaction', (data) => {
    if (!data || typeof data.messageId !== 'string' || typeof data.reaction !== 'string') return;
    if (data.reaction.length > 20) return;

    const { messageId, reaction } = data;
    const targetMessage = messages.find(m => m.id === messageId);
    
    if (targetMessage) {
      if (!targetMessage.reactions) {
        targetMessage.reactions = {};
      }
      
      const currentCount = targetMessage.reactions[reaction] || 0;
      if (currentCount < 9999) {
        targetMessage.reactions[reaction] = currentCount + 1;
      }

      io.emit('updateReaction', {
        messageId: messageId,
        reactions: targetMessage.reactions
      });
    }
  });

  socket.on('disconnect', () => {
    activeConnections = Math.max(0, activeConnections - 1);
    io.emit('userCount', { userCount: activeConnections });
  });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(` Sennin BBS / Secure Backend Active `);
});
