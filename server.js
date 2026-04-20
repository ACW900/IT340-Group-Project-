const express       = require('express');
const mongoose      = require('mongoose');
const cors          = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const validator     = require('validator');

const app = express();

app.use(cors({ origin: 'http://192.168.199.131' }));
app.use(express.json());
app.use(mongoSanitize());

mongoose.connect('mongodb://192.168.201.133:27017/gameatlas')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// ── Schemas ────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  fname:    { type: String, required: true },
  lname:    { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const cacheSchema = new mongoose.Schema({
  key:      { type: String, required: true, unique: true },
  data:     { type: mongoose.Schema.Types.Mixed, required: true },
  cachedAt: { type: Date, default: Date.now }
});
const Cache = mongoose.model('Cache', cacheSchema);

const CACHE_TTL_MS = 60 * 60 * 1000;

// ── Register ───────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    let { fname, lname, username, email, password } = req.body;

    fname    = validator.escape(fname.trim());
    lname    = validator.escape(lname.trim());
    username = validator.escape(username.trim());
    email    = validator.normalizeEmail(email.trim());

    if (!validator.isEmail(email))
      return res.status(400).json({ message: 'Invalid email address.' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ message: 'Invalid username.' });
    if (!password || password.length !== 64)
      return res.status(400).json({ message: 'Invalid password format.' });

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing)
      return res.status(409).json({ message: 'Email or username already in use.' });

    const user = new User({ fname, lname, username, email, password });
    await user.save();

    res.status(201).json({ message: 'Account created successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Login ──────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body;

    email = validator.normalizeEmail(email.trim());

    if (!validator.isEmail(email))
      return res.status(400).json({ message: 'Invalid email address.' });
    if (!password || password.length !== 64)
      return res.status(400).json({ message: 'Invalid password format.' });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ message: 'Invalid email or password.' });

    if (password !== user.password)
      return res.status(401).json({ message: 'Invalid email or password.' });

    res.json({
      message: 'Login successful.',
      user: { email: user.email, name: user.username }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ── Cache GET ──────────────────────────────────────────────────────────
app.get('/api/cache/:key', async (req, res) => {
  try {
    const entry = await Cache.findOne({ key: req.params.key });
    if (!entry)
      return res.status(404).json({ message: 'No cache found.' });

    const ageMs = Date.now() - new Date(entry.cachedAt).getTime();
    const fresh = ageMs < CACHE_TTL_MS;

    res.json({ data: entry.data, cachedAt: entry.cachedAt, ageMs, fresh });
  } catch (err) {
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
    res.json({ message: 'Cache updated.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));