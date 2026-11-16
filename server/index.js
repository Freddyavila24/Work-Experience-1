
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const { sendToSupport } = require('./support');

const app = express();
const PORT = process.env.PORT || 3000;
const FORM_SECRET = process.env.FORM_SECRET;
const MIN_FORM_TIME = 3000; // 3 seconds

if (!FORM_SECRET) {
  throw new Error('FORM_SECRET environment variable is required');
}

function signTimestamp(timestamp) {
  return crypto
    .createHmac('sha256', FORM_SECRET)
    .update(String(timestamp))
    .digest('hex');
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  express.static(path.join(__dirname, '..', 'public'), {
    extensions: ['html']
  })
);

// Generate a signed timestamp when the form loads
app.get('/contact-token', (req, res) => {
  const timestamp = Date.now();

  res.set('Cache-Control', 'no-store');

  res.json({
    timestamp,
    signature: signTimestamp(timestamp)
  });
});

// Handle contact form submissions
app.post('/contact', (req, res) => {
  const website = req.body.website;
  const timestamp = req.body.timestamp;
  const signature = req.body.signature;

  // Return the normal success response for spam
  const silentSuccess = () => res.json({ ok: true });

  // Check 1: Honeypot
  if (typeof website !== 'string' || website.trim() !== '') {
    return silentSuccess();
  }

  // Check 2: Validate timestamp and signature
  if (
    typeof timestamp !== 'string' ||
    !/^\d{13}$/.test(timestamp) ||
    typeof signature !== 'string' ||
    !/^[a-f0-9]{64}$/.test(signature)
  ) {
    return silentSuccess();
  }

  const expectedSignature = signTimestamp(timestamp);

  if (
    !crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    )
  ) {
    return silentSuccess();
  }

  const elapsed = Date.now() - Number(timestamp);

  // Reject submissions under 3 seconds or over 1 hour
  if (elapsed < MIN_FORM_TIME || elapsed > 60 * 60 * 1000) {
    return silentSuccess();
  }

  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim();
  const message = (req.body.message || '').trim();

  if (!name || !email || !message) {
    return res.status(400).json({
      ok: false,
      error: 'Please fill in your name, email and message.'
    });
  }

  sendToSupport({ name, email, message });

  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Calico Media site running at http://localhost:${PORT}`);
});
