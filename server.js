'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

// 管理用パスワード（全削除および管理者ログイン用）
const ADMIN_PASSWORD = 'senninv1';

// サーバー側データストア（メモリ上に保持）
let messages = [];
let activeConnections = 0;

// ミドルウェア設定
app.use(cors({
  origin: '*', // 開発・テスト用にすべて許可（必要に応じて制限してください）
  methods: ['GET', 'POST']
}));
app.use(express.json());

// 1. [GET] 投稿一覧の取得
app.get('/api/messages', (req, res) => {
  res.json(messages);
});

// 2. [POST] 新規投稿の受付
app.post('/api/messages', (req, res) => {
  const { username, message, time, seed } = req.body;

  // バリデーション
  if (!username || !message || !time || !seed) {
    return res.status(400).json({ error: '必要なフィールドが不足しています。' });
  }

  const newPost = {
    username: String(username).substring(0, 24),
    message: String(message).substring(0, 1000),
    time: String(time),
    seed: String(seed),
    reactions: {} // リアクションの初期状態
  };

  messages.push(newPost);

  // 全クライアントへリアルタイム通知
  io.emit('newMessage', newPost);

  res.status(201).json({ success: true, message: '投稿が完了しました。' });
});

// 3. [POST] パスワード認証（全削除・管理者ログイン共通）
app.post('/api/pass', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: 'パスワードを入力してください' });
  }

  if (password === ADMIN_PASSWORD) {
    // リクエスト元が削除処理（x-requested-withヘッダーなど）を伴う場合はデータをクリア
    if (req.headers['x-requested-with'] === 'fetch') {
      // 厳密にURLやパラメータで分けることも可能ですが、元の挙動に合わせ一括削除をトリガー可能に
      // クライアント側から「全メッセージ削除」ボタン経由で叩かれた場合のハンドリング
      if (req.body.password === ADMIN_PASSWORD && !req.body.justAuth) {
        messages = [];
        io.emit('clearMessages');
        return res.json({ message: '履歴を削除しました' });
      }
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

// Socket.IO 設定（フロントエンドに合わせてpollingを許容）
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  allowEIO3: true
});

io.on('connection', (socket) => {
  activeConnections++;
  io.emit('userCount', { userCount: activeConnections }); // フロント接続時のカウント更新用

  // リアクションの更新処理
  socket.on('updateReaction', (data) => {
    if (!data || typeof data.messageId !== 'number') return;
    
    const { messageId, reaction } = data;
    
    // 対象の投稿が存在するかチェック
    if (messages[messageId]) {
      if (!messages[messageId].reactions) {
        messages[messageId].reactions = {};
      }
      
      // カウントをインクリメント
      const currentCount = messages[messageId].reactions[reaction] || 0;
      messages[messageId].reactions[reaction] = currentCount + 1;

      // 全クライアントにリアクション結果を同期
      io.emit('updateReaction', {
        messageId: messageId,
        reactions: messages[messageId].reactions
      });
    }
  });

  socket.on('disconnect', () => {
    activeConnections = Math.max(0, activeConnections - 1);
  });
});

// サーバー起動（ポートは環境変数または3000）
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`-----------------------------------------`);
  console.log(` Sennin BBS / min2 Chat Backend Server`);
  console.log(` Running on port: ${PORT}`);
  console.log(` Admin Password is: ${ADMIN_PASSWORD}`);
  console.log(`-----------------------------------------`);
});
