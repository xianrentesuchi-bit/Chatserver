'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
require('dotenv').config(); // 環境変数の読み込み用

const app = express();
const server = http.createServer(app);

// 1. 基本的なセキュリティヘッダーの付与
app.use(helmet());

// 2. CORSの制限 (信頼できるドメインのみ許可)
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

// ペイロードサイズを制限してDoS攻撃を防止
app.use(express.json({ limit: '10kb' }));

// 3. レートリミット（連投・総当たり攻撃対策）
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分
  max: 100, // IPごとに最大100リクエスト
  message: { error: 'リクエストが多すぎます。しばらく時間をおいてお試しください。' }
});
app.use('/api/', apiLimiter);

// ★【変更点】環境変数から生のパスワードを取得し、起動時にハッシュ化する
const RAW_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; 
const ADMIN_PASSWORD_HASH = crypto.createHash('sha256').update(RAW_PASSWORD).digest('hex');

// メモリ枯渇を防ぐため、最大保持件数を設定
const MAX_MESSAGES = 500;
let messages = [];
let activeConnections = 0;

// 1. [GET] 投稿一覧の取得
app.get('/api/messages', (req, res) => {
  res.json(messages);
});

// 2. [POST] 新規投稿の受付（バリデーションとサニタイズを徹底）
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
    id: crypto.randomUUID(), // インデックス依存を排除し、予測不可能なUUIDを付与
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

// 3. [POST] パスワード認証および削除処理
app.post('/api/pass', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: 'パスワードを入力してください' });
  }

  // 入力されたパスワードをハッシュ化して比較用にする
  const inputHash = crypto.createHash('sha256').update(password).digest('hex');
  
  // 安全な固定時間比較（タイミング攻撃対策）
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

// 4. [GET] オンラインユーザー数の取得
app.get('/user', (req, res) => {
  res.json({ userCount: activeConnections });
});

// Socket.IO 構成の最適化
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
