'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

// 管理用パスワード設定
const ADMIN_PASSWORD = 'admin123';

let messages = [];
let activeConnections = 0;

app.use(cors({
  origin: '*', 
  methods: ['GET', 'POST'],
  credentials: true
}));
app.use(express.json());

// 1. [GET] 投稿一覧の取得
app.get('/api/messages', (req, res) => {
  res.json(messages);
});

// 2. [POST] 新規投稿の受付
app.post('/api/messages', (req, res) => {
  const { username, message, time, seed } = req.body;

  if (!username || !message || !time || !seed) {
    return res.status(400).json({ error: '必要なフィールドが不足しています。' });
  }

  const newPost = {
    username: String(username).substring(0, 24),
    message: String(message).substring(0, 1000),
    time: String(time),
    seed: String(seed),
    reactions: {}
  };

  messages.push(newPost);
  io.emit('newMessage', newPost);

  res.status(201).json({ success: true, message: '投稿が完了しました。' });
});

// 3. [POST] パスワード認証および削除処理
app.post('/api/pass', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: 'パスワードを入力してください' });
  }

  if (password === ADMIN_PASSWORD) {
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

// 4. [GET] オンラインユーザー数の取得
app.get('/user', (req, res) => {
  res.json({ userCount: activeConnections });
});

// Socket.IO 構成の最適化 (websocket優先)
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true
});

io.on('connection', (socket) => {
  activeConnections++;
  io.emit('userCount', { userCount: activeConnections });

  socket.on('updateReaction', (data) => {
    if (!data || typeof data.messageId !== 'number') return;
    
    const { messageId, reaction } = data;
    
    if (messages[messageId]) {
      if (!messages[messageId].reactions) {
        messages[messageId].reactions = {};
      }
      
      const currentCount = messages[messageId].reactions[reaction] || 0;
      messages[messageId].reactions[reaction] = currentCount + 1;

      io.emit('updateReaction', {
        messageId: messageId,
        reactions: messages[messageId].reactions
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
  console.log(`-----------------------------------------`);
  console.log(` Sennin BBS / Backend Server Active`);
  console.log(` Running on port: ${PORT}`);
  console.log(`-----------------------------------------`);
});
