/**
 * api/mailgun-inbound.js — Receives Mailgun inbound webhook, extracts
 * Greenhouse security codes, writes them to Supabase.
 *
 * Mailgun POSTs inbound email as multipart/form-data with fields:
 *   sender, recipient, subject, body-plain, stripped-text, timestamp,
 *   token, signature (for verification), etc.
 *
 * Deploy: this file lives at /api/mailgun-inbound.js in a Vercel project.
 * Vercel auto-detects files under /api as serverless functions.
 *
 * Env vars needed in Vercel project settings:
 *   SUPABASE_URL
 *   SUPABASE_ANON_KEY
 *   MAILGUN_SIGNING_KEY   (optional but recommended, for request verification)
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

function log(msg) { console.log(`[${new Date().toISOString()}] ${msg}`); }

// Verify the request actually came from Mailgun using their signing key.
// If MAILGUN_SIGNING_KEY isn't set, this check is skipped (not recommended
// for production, but fine while testing).
function verifyMailgunSignature(timestamp, token, signature) {
  const signingKey = process.env.MAILGUN_SIGNING_KEY;
  if (!signingKey) return true; // skip verification if key not configured

  const encodedToken = crypto
    .createHmac('sha256', signingKey)
    .update(timestamp + token)
    .digest('hex');

  return encodedToken === signature;
}

// Extract Greenhouse security code from email body.
// Pattern observed: "security code field on your application: XXXXXXXX"
// Code is always 8 characters, mixed-case alphanumeric.
function extractSecurityCode(text) {
  if (!text) return null;
  const match = text.match(/security code field on your application:\s*([A-Za-z0-9]{8})/i);
  return match ? match[1] : null;
}

// Vercel serverless function handler (Node.js runtime, CommonJS)
module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  try {
    const body = req.body || {};

    const sender = body.sender || body.from || '';
    const recipient = body.recipient || '';
    const subject = body.subject || '';
    const bodyPlain = body['body-plain'] || body.bodyPlain || '';
    const strippedText = body['stripped-text'] || body.strippedText || '';
    const timestamp = body.timestamp || '';
    const token = body.token || '';
    const signature = body.signature || '';

    log(`Inbound email from=${sender} to=${recipient} subject="${subject.slice(0, 60)}"`);

    // Verify signature if configured
    if (process.env.MAILGUN_SIGNING_KEY) {
      const valid = verifyMailgunSignature(timestamp, token, signature);
      if (!valid) {
        log('  Signature verification failed — rejecting');
        res.status(401).json({ error: 'Invalid signature' });
        return;
      }
    }

    // Only process emails that look like Greenhouse security code emails
    const isGreenhouse = sender.includes('greenhouse-mail.io') || sender.includes('greenhouse.io');
    const isSecurityCodeEmail = /security code/i.test(subject);

    if (!isGreenhouse || !isSecurityCodeEmail) {
      log('  Not a Greenhouse security code email — skipping extraction, still 200 OK');
      res.status(200).json({ status: 'ignored', reason: 'not a security code email' });
      return;
    }

    // Try stripped-text first (cleaner), fall back to body-plain
    const code = extractSecurityCode(strippedText) || extractSecurityCode(bodyPlain);

    if (!code) {
      log('  Could not extract code from email body');
      res.status(200).json({ status: 'no_code_found' });
      return;
    }

    log(`  Extracted code: ${code}`);

    // Write to Supabase
    const { error } = await supabase.from('security_codes').insert({
      code,
      sender,
      recipient,
      subject,
      received_at: new Date().toISOString(),
    });

    if (error) {
      log(`  Supabase insert error: ${error.message}`);
      res.status(500).json({ error: 'Failed to store code' });
      return;
    }

    log('  Code stored successfully');
    res.status(200).json({ status: 'ok', code_stored: true });
  } catch (err) {
    log(`  Handler error: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
};
