const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const validator = require('validator');
const winston   = require('winston');
const nodemailer = require('nodemailer');
const crypto    = require('crypto');
require('winston-syslog');

const app = express();

// ── Logger ─────────────────────────────────────────────────────────────
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.Syslog({
      host:     '192.168.199.134',
      port:     514,
      protocol: 'udp4',
      app_name: 'gameatlas',
      facility: 'local0',
      type:     'BSD'
    })
  ]
});

// ── Mailer ─────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'gameatlasemail@gmail.com',
    pass: 'fezq prdj befw hrqy'
  }
});

app.use(cors({ origin: 'http://192.168.199.131' }));
app.use(express.json());

// ── Manual NoSQL injection sanitization ───────────────────────────────
app.use((req, res, next) => {
  if (req.body) {
    const sanitize = (obj, skipKeys = []) => {
      Object.keys(obj).forEach(key => {
        if (skipKeys.includes(key)) return;
        if (typeof obj[key] === 'string') {
          obj[key] = obj[key].replace(/\$/g, '');
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitize(obj[key], skipKeys);
        }
      });
    };
    sanitize(req.body, ['email']);
  }
  next();
});

mongoose.connect('mongodb://192.168.199.133:27017/gameatlas')
  .then(() => logger.info('MongoDB connected'))
  .catch(err => logger.error(err));

// ── Schemas ────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  fname:         { type: String, required: true },
  lname:         { type: String, required: true },
  username:      { type: String, required: true, unique: true },
  email:         { type: String, required: true, unique: true },
  password:      { type: String, required: true },
  verified:      { type: Boolean, default: false },
  verifyToken:   { type: String, default: null },
  verifyExpires: { type: Date,   default: null }
});
const User = mongoose.model('User', userSchema);

const wishlistItemSchema = new mongoose.Schema({
  gameID: { type: String, required: true },
  title:  { type: String, required: true },
  thumb:  { type: String, default: '' }
});

const wishlistSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  games:  { type: [wishlistItemSchema], default: [] }
});
const Wishlist = mongoose.model('Wishlist', wishlistSchema);

const cacheSchema = new mongoose.Schema({
  key:      { type: String, required: true, unique: true },
  data:     { type: mongoose.Schema.Types.Mixed, required: true },
  cachedAt: { type: Date, default: Date.now }
});
const Cache = mongoose.model('Cache', cacheSchema);

const CACHE_TTL_MS = 60 * 60 * 1000;

// ── Log helper ─────────────────────────────────────────────────────────
function maskEmail(email) {
  const [local, domain] = email.split('@');
  const masked = local[0] + '***' + local[local.length - 1];
  return `${masked}@${domain}`;
}

// ── Register ───────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    let { fname, lname, username, email, password } = req.body;

    logger.info(`[REGISTER] attempt | email:${maskEmail(email)} | username:${username} | ip:${req.ip}`);

    fname    = validator.escape(fname.trim());
    lname    = validator.escape(lname.trim());
    username = validator.escape(username.trim());
    email    = email.trim();

    if (!validator.isEmail(email))
      return res.status(400).json({ message: 'Invalid email address.' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ message: 'Invalid username.' });
    if (!password || password.length === 0)
      return res.status(400).json({ message: 'Invalid password format.' });

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing)
      return res.status(409).json({ message: 'Email or username already in use.' });

    // Generate verification token
    const verifyToken   = crypto.randomBytes(32).toString('hex');
    const verifyExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    const user = new User({ fname, lname, username, email, password, verifyToken, verifyExpires });
    await user.save();

    // Create empty wishlist for new user
    await Wishlist.create({ userId: user._id, games: [] });

    // Send verification email
    const verifyURL = `http://192.168.199.131/verify.html?token=${verifyToken}`;
    await transporter.sendMail({
      from:    '"GameAtlas" <gameatlasemail@gmail.com>',
      to:      email,
      subject: 'Verify your GameAtlas account',
      html: `
        <h2>Welcome to GameAtlas, ${username}!</h2>
        <p>Click the button below to verify your email address.</p>
        <a href="${verifyURL}" style="background:#6c63ff;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;">
          Verify my account
        </a>
        <p>This link expires in 1 hour.</p>
        <p>If you did not create this account you can ignore this email.</p>
      `
    });

    logger.info(`[REGISTER] success → 201 | user:${user._id} | username:${user.username} | ip:${req.ip}`);
    res.status(201).json({ message: 'Account created. Please check your email to verify.' });
  } catch (err) {
    logger.error(`[REGISTER] error → 500 | error:${err.message} | ip:${req.ip}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Verify Email ───────────────────────────────────────────────────────
app.get('/api/verify', async (req, res) => {
  try {
    const { token } = req.query;

    if (!token)
      return res.status(400).json({ message: 'No token provided.' });

    const user = await User.findOne({ verifyToken: token });

    if (!user)
      return res.status(400).json({ message: 'Invalid or expired token.' });

    if (new Date() > user.verifyExpires)
      return res.status(400).json({ message: 'Token has expired. Please register again.' });

    user.verified      = true;
    user.verifyToken   = null;
    user.verifyExpires = null;
    await user.save();

    logger.info(`[VERIFY] success → 200 | user:${user._id} | username:${user.username} | ip:${req.ip}`);
    res.json({ message: 'Email verified successfully.' });
  } catch (err) {
    logger.error(`[VERIFY] error → 500 | error:${err.message} | ip:${req.ip}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Login ──────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    email = email.trim();

    if (!validator.isEmail(email))
      return res.status(400).json({ message: 'Invalid email address.' });
    if (!password || password.length === 0)
      return res.status(400).json({ message: 'Invalid password format.' });

    const user = await User.findOne({ email });
    if (!user) {
      logger.warn(`[LOGIN] failed → 401 | email:${maskEmail(email)} | reason:user_not_found | ip:${req.ip}`);
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    if (password !== user.password) {
      logger.warn(`[LOGIN] failed → 401 | user:${user._id} | username:${user.username} | reason:wrong_password | ip:${req.ip}`);
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    if (!user.verified) {
      logger.warn(`[LOGIN] blocked → 403 | user:${user._id} | username:${user.username} | reason:unverified | ip:${req.ip}`);
      return res.status(403).json({ message: 'Please verify your email before logging in.' });
    }

    logger.info(`[LOGIN] success → 200 | user:${user._id} | username:${user.username} | ip:${req.ip}`);
    res.json({
      message: 'Login successful.',
      user: { id: user._id, email: user.email, name: user.username }
    });
  } catch (err) {
    logger.error(`[LOGIN] error → 500 | error:${err.message} | ip:${req.ip}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Wishlist GET ───────────────────────────────────────────────────────
app.get('/api/wishlist/:userId', async (req, res) => {
  try {
    const wishlist = await Wishlist.findOne({ userId: req.params.userId });
    if (!wishlist)
      return res.status(404).json({ message: 'Wishlist not found.' });
    res.json({ games: wishlist.games });
  } catch (err) {
    logger.error(`GET /api/wishlist → 500 | error:${err.message}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Wishlist ADD ───────────────────────────────────────────────────────
app.post('/api/wishlist/:userId/add', async (req, res) => {
  try {
    const { gameID, title, thumb } = req.body;

    if (!gameID || !title)
      return res.status(400).json({ message: 'gameID and title are required.' });

    const wishlist = await Wishlist.findOne({ userId: req.params.userId });
    if (!wishlist)
      return res.status(404).json({ message: 'Wishlist not found.' });

    const already = wishlist.games.find(g => g.gameID === gameID);
    if (already)
      return res.status(409).json({ message: 'Game already in wishlist.' });

    wishlist.games.push({ gameID, title, thumb: thumb || '' });
    await wishlist.save();

    logger.info(`POST /api/wishlist/add → 200 | user:${req.params.userId} | game:${gameID}`);
    res.json({ message: 'Added to wishlist.', games: wishlist.games });
  } catch (err) {
    logger.error(`POST /api/wishlist/add → 500 | error:${err.message}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Wishlist REMOVE ────────────────────────────────────────────────────
app.delete('/api/wishlist/:userId/remove/:gameID', async (req, res) => {
  try {
    const wishlist = await Wishlist.findOne({ userId: req.params.userId });
    if (!wishlist)
      return res.status(404).json({ message: 'Wishlist not found.' });

    wishlist.games = wishlist.games.filter(g => g.gameID !== req.params.gameID);
    await wishlist.save();

    logger.info(`DELETE /api/wishlist/remove → 200 | user:${req.params.userId} | game:${req.params.gameID}`);
    res.json({ message: 'Removed from wishlist.', games: wishlist.games });
  } catch (err) {
    logger.error(`DELETE /api/wishlist/remove → 500 | error:${err.message}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Wishlist CLEAR ─────────────────────────────────────────────────────
app.delete('/api/wishlist/:userId/clear', async (req, res) => {
  try {
    const wishlist = await Wishlist.findOne({ userId: req.params.userId });
    if (!wishlist)
      return res.status(404).json({ message: 'Wishlist not found.' });

    wishlist.games = [];
    await wishlist.save();

    logger.info(`DELETE /api/wishlist/clear → 200 | user:${req.params.userId}`);
    res.json({ message: 'Wishlist cleared.' });
  } catch (err) {
    logger.error(`DELETE /api/wishlist/clear → 500 | error:${err.message}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Cache GET ──────────────────────────────────────────────────────────
app.get('/api/cache/:key', async (req, res) => {
  try {
    const entry = await Cache.findOne({ key: req.params.key });
    if (!entry) {
      logger.info(`GET /api/cache/${req.params.key} → 404 | ip:${req.ip}`);
      return res.status(404).json({ message: 'No cache found.' });
    }

    const ageMs = Date.now() - new Date(entry.cachedAt).getTime();
    const fresh = ageMs < CACHE_TTL_MS;

    logger.info(`GET /api/cache/${req.params.key} → 200 | fresh:${fresh} | ip:${req.ip}`);
    res.json({ data: entry.data, cachedAt: entry.cachedAt, ageMs, fresh });
  } catch (err) {
    logger.error(`GET /api/cache → 500 | error:${err.message}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Cache POST ─────────────────────────────────────────────────────────
app.post('/api/cache/:key', async (req, res) => {
  try {
    const { data } = req.body;
    await Cache.findOneAndUpdate(
      { key: req.params.key },
      { data, cachedAt: new Date() },
      { upsert: true, new: true }
    );
    logger.info(`POST /api/cache/${req.params.key} → 200 | ip:${req.ip}`);
    res.json({ message: 'Cache updated.' });
  } catch (err) {
    logger.error(`POST /api/cache → 500 | error:${err.message}`);
    res.status(500).json({ message: 'Server error.' });
  }
});

app.listen(3000, () => logger.info('Server running on port 3000'));

