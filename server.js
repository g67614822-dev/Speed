import express from 'express';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { jsPDF } from 'jspdf';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'token-send-secret-change-me';

// Chemin DB pour Railway Volume. Si pas défini, utilise local
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'db.json');

const adapter = new JSONFile(DB_PATH);
const db = new Low(adapter, {
  users: [],
  blogs: [],
  exchanges: [],
  settings: [{ id: 1, admin_password: bcrypt.hashSync('tsila123', 10) }]
});
await db.read();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Middleware auth user
const auth = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
};

// Middleware auth admin
const adminAuth = (req, res, next) => {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
};

// LOGIN UNIQUE : crée en pending si n'existe pas
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if(!email ||!password) return res.status(400).json({ error: 'Remplis tout' });

  let user = db.data.users.find(u => u.email === email);

  if (!user) {
    const hashed = bcrypt.hashSync(password, 10);
    user = {
      id: Date.now(),
      email,
      password: hashed,
      tokens: 0,
      gold: 0,
      status: 'pending',
      created_at: new Date().toISOString()
    };
    db.data.users.push(user);
    await db.write();
    return res.status(403).json({ error: 'Compte en attente de confirmation admin' });
  }

  if(user.status!== 'confirmed') {
    return res.status(403).json({ error: 'Compte en attente de confirmation admin' });
  }

  if(user.status === 'blocked') {
    return res.status(403).json({ error: 'Compte bloqué' });
  }

  if(!bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: 'Mot de passe incorrect' });
  }

  const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
  res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.data.users.find(u => u.id === req.user.id);
  const { password,...safeUser } = user;
  res.json(safeUser);
});

// Défi quotidien
app.post('/api/claim-daily', auth, async (req, res) => {
  const today = new Date().toISOString().split('T')[0];

  const exists = db.data.exchanges.find(e => {
    if (e.user_id!== req.user.id || e.type!== 'daily') return false;
    const dateStr = new Date(e.created_at).toISOString().split('T')[0];
    return dateStr === today;
  });

  if (exists) return res.status(400).json({ error: 'Déjà réclamé aujourd\'hui' });

  const user = db.data.users.find(u => u.id === req.user.id);
  user.tokens += 2;
  db.data.exchanges.push({
    id: Date.now(),
    user_id: req.user.id,
    type: 'daily',
    amount: 2,
    status: 'accepted',
    created_at: new Date().toISOString()
  });
  await db.write();
  res.json({ success: true });
});

// Échange
app.post('/api/exchange', auth, async (req, res) => {
  const { type, uid, pseudo } = req.body;
  const user = db.data.users.find(u => u.id === req.user.id);

  if (type === 'tokens') {
    if (user.tokens < 20) return res.status(400).json({ error: 'Pas assez de jetons' });
    user.tokens -= 20;
    user.gold += 1;
    db.data.exchanges.push({
      id: Date.now(),
      user_id: req.user.id,
      type: 'token_to_gold',
      amount: 20,
      status: 'accepted',
      created_at: new Date().toISOString()
    });
  } else {
    if (user.gold < 1) return res.status(400).json({ error: 'Pas assez d\'or' });
    user.gold -= 1;
    db.data.exchanges.push({
      id: Date.now(),
      user_id: req.user.id,
      type,
      amount: 1,
      uid,
      pseudo,
      status: 'pending',
      created_at: new Date().toISOString()
    });
  }
  await db.write();
  res.json({ success: true });
});

app.get('/api/history', auth, (req, res) => {
  const rows = db.data.exchanges.filter(e => e.user_id === req.user.id).reverse();
  res.json(rows);
});

app.get('/api/blogs', (req, res) => {
  res.json(db.data.blogs.reverse());
});

// ADMIN LOGIN
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  const settings = db.data.settings[0];
  if (!bcrypt.compareSync(password, settings.admin_password)) {
    return res.status(400).json({ error: 'Mot de passe incorrect' });
  }
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('admin_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
  res.json({ success: true });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = db.data.users.map(u => {
    const { password,...safe } = u;
    return safe;
  }).reverse();
  res.json(users);
});

// Confirmer/Bloquer un user
app.post('/api/admin/confirm-user', adminAuth, async (req, res) => {
  const { userId, status } = req.body;
  const user = db.data.users.find(u => u.id === userId);
  if(user){
    user.status = status;
    await db.write();
  }
  res.json({ success: true });
});

// Donner jetons/or
app.post('/api/admin/add-tokens', adminAuth, async (req, res) => {
  const { userId, tokens, gold } = req.body;
  const user = db.data.users.find(u => u.id === userId);
  if (user) {
    user.tokens += tokens || 0;
    user.gold += gold || 0;
    await db.write();
  }
  res.json({ success: true });
});

// Récupérer tous les échanges pour admin
app.get('/api/admin/exchanges', adminAuth, (req, res) => {
  const exchanges = db.data.exchanges.map(e => {
    const user = db.data.users.find(u => u.id === e.user_id);
    return {
    ...e,
      email: user?.email || 'Inconnu'
    };
  }).reverse();
  res.json(exchanges);
});

// Accepter/Rejeter échange
app.post('/api/admin/update-exchange', adminAuth, async (req, res) => {
  const { exchangeId, status } = req.body;
  const exchange = db.data.exchanges.find(e => e.id === exchangeId);
  if(exchange){
    exchange.status = status;
    if(status === 'rejected' && exchange.type!== 'token_to_gold' && exchange.type!== 'daily'){
      const user = db.data.users.find(u => u.id === exchange.user_id);
      if(user) user.gold += exchange.amount;
    }
    await db.write();
  }
  res.json({ success: true });
});

// Ajouter blog
app.post('/api/admin/add-blog', adminAuth, async (req, res) => {
  const { title, description, url } = req.body;
  db.data.blogs.push({
    id: Date.now(),
    title,
    description,
    url,
    created_at: new Date().toISOString()
  });
  await db.write();
  res.json({ success: true });
});

// Paramètres
app.post('/api/admin/settings', adminAuth, async (req, res) => {
  const { site_logo, ff_logo, pubg_logo, subscribe_link } = req.body;
  Object.assign(db.data.settings[0], { site_logo, ff_logo, pubg_logo, subscribe_link });
  await db.write();
  res.json({ success: true });
});

// Changer mdp admin
app.post('/api/admin/change-password', adminAuth, async (req, res) => {
  db.data.settings[0].admin_password = bcrypt.hashSync(req.body.password, 10);
  await db.write();
  res.json({ success: true });
});

// Export PDF
app.get('/api/admin/export-pdf', adminAuth, (req, res) => {
  const doc = new jsPDF();
  doc.setFontSize(16);
  doc.text('Users - Token Send', 10, 10);
  let y = 20;
  db.data.users.forEach(u => {
    doc.setFontSize(10);
    doc.text(`${u.email} | Status:${u.status} | Tokens:${u.tokens} | Or:${u.gold}`, 10, y);
    y += 8;
    if (y > 280) { doc.addPage(); y = 20; }
  });
  res.setHeader('Content-Type', 'application/pdf');
  res.send(Buffer.from(doc.output('arraybuffer')));
});

app.get('/api/settings', (req, res) => {
  const { site_logo, ff_logo, pubg_logo, subscribe_link } = db.data.settings[0];
  res.json({ site_logo, ff_logo, pubg_logo, subscribe_link });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
