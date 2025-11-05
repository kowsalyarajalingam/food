const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { nanoid } = require('nanoid');

// lowdb setup (v1)
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('db.json');
const db = low(adapter);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Initialize defaults
db.defaults({ users: [], products: [], orders: [] }).write();

// Ensure admin password is set (default admin: admin123)
(function ensureAdmin() {
  const admin = db.get('users').find({ username: 'admin' }).value();
  if (admin) {
    if (!admin.passwordHash) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.get('users').find({ username: 'admin' }).assign({ passwordHash: hash, id: 'u_admin' }).write();
      console.log('Admin user created with username=admin and password=admin123');
    }
  } else {
    const hash = bcrypt.hashSync('admin123', 10);
    db.get('users').push({ id: 'u_admin', username: 'admin', passwordHash: hash, isAdmin: true }).write();
    console.log('Admin user created with username=admin and password=admin123');
  }
})();

// Auth helpers
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, isAdmin: !!user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Missing authorization header' });
  const parts = header.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Invalid authorization header' });
  const token = parts[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Routes
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const exists = db.get('users').find({ username }).value();
  if (exists) return res.status(400).json({ error: 'username already exists' });
  const hash = bcrypt.hashSync(password, 10);
  const user = { id: nanoid(), username, passwordHash: hash, isAdmin: false };
  db.get('users').push(user).write();
  const token = generateToken(user);
  res.json({ token, user: { id: user.id, username: user.username, isAdmin: user.isAdmin } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const user = db.get('users').find({ username }).value();
  if (!user) return res.status(400).json({ error: 'invalid credentials' });
  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'invalid credentials' });
  const token = generateToken(user);
  res.json({ token, user: { id: user.id, username: user.username, isAdmin: user.isAdmin } });
});

// Products
app.get('/api/products', (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  let products = db.get('products').value();
  if (q) {
    products = products.filter(p => p.name.toLowerCase().includes(q) || p.restaurant.toLowerCase().includes(q));
  }
  res.json(products);
});

app.get('/api/products/:id', (req, res) => {
  const p = db.get('products').find({ id: req.params.id }).value();
  if (!p) return res.status(404).json({ error: 'not found' });
  res.json(p);
});

app.post('/api/products', authMiddleware, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  const { name, restaurant, price, image, description, featured } = req.body;
  const product = { id: nanoid(), name, restaurant, price: Number(price), image, description, featured: !!featured };
  db.get('products').push(product).write();
  res.json(product);
});

app.put('/api/products/:id', authMiddleware, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  const updates = req.body;
  db.get('products').find({ id: req.params.id }).assign(updates).write();
  const p = db.get('products').find({ id: req.params.id }).value();
  res.json(p);
});

app.delete('/api/products/:id', authMiddleware, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  db.get('products').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// Orders
app.post('/api/orders', authMiddleware, (req, res) => {
  const { items, delivery, payment } = req.body;
  if (!items || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'cart empty' });
  const total = items.reduce((s, it) => s + (it.price * it.quantity), 0);
  const order = {
    id: nanoid(),
    userId: req.user.id,
    items,
    // delivery may include name, address, city, phone
    delivery,
    payment,
    total,
    status: 'received',
    createdAt: new Date().toISOString()
  };
  db.get('orders').push(order).write();
  res.json({ orderId: order.id, status: order.status });
});

app.get('/api/orders/:id', authMiddleware, (req, res) => {
  const order = db.get('orders').find({ id: req.params.id }).value();
  if (!order) return res.status(404).json({ error: 'not found' });
  if (order.userId !== req.user.id && !req.user.isAdmin) return res.status(403).json({ error: 'forbidden' });
  res.json(order);
});

// Admin: list all orders
app.get('/api/orders', authMiddleware, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  const orders = db.get('orders').value();
  res.json(orders);
});

// Admin: update order (status, delivery notes, etc.)
app.put('/api/orders/:id', authMiddleware, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  const updates = req.body || {};
  // allow updating status and delivery info
  const allowed = {};
  if (updates.status) allowed.status = updates.status;
  if (updates.delivery) allowed.delivery = updates.delivery;
  if (updates.payment) allowed.payment = updates.payment;
  db.get('orders').find({ id: req.params.id }).assign(allowed).write();
  const order = db.get('orders').find({ id: req.params.id }).value();
  if (!order) return res.status(404).json({ error: 'not found' });
  res.json(order);
});

// Fallback to index.html for SPA
app.get('*', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(PORT, () => {
  console.log('FoodHub server running on port', PORT);
});
