/**
 * api/mailgun-inbound.js — Receives Mailgun inbound webhook.
 * Handles THREE email types:
 *   1. Greenhouse security code emails -> writes to `security_codes` table
 *   2. LinkedIn job alert digests      -> parses listings, writes to `applications` (queued)
 *   3. Welcome to the Jungle job alert digests -> same as above
 *
 * DETECTION NOTE: LinkedIn/WTTJ alerts are identified by the actual body
 * content (presence of their distinctive job-link URL pattern), NOT by
 * sender address or subject line. This is because a manually-forwarded
 * email rewrites the sender to the forwarder (you) and prepends "Fwd:" to
 * the subject -- confirmed from a real captured forward, where sender
 * showed as afilous22@gmail.com with subject "Fwd: ...". Checking body
 * content instead works regardless of how the email arrives (manual
 * forward, Gmail auto-filter, etc.).
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

function verifyMailgunSignature(timestamp, token, signature) {
  const signingKey = process.env.MAILGUN_SIGNING_KEY;
  if (!signingKey) return true;
  const encodedToken = crypto
    .createHmac('sha256', signingKey)
    .update(timestamp + token)
    .digest('hex');
  return encodedToken === signature;
}

function extractSecurityCode(text) {
  if (!text) return null;
  const match = text.match(/security code field on your application:\s*([A-Za-z0-9]{8})/i);
  return match ? match[1] : null;
}

function parseLinkedInJobs(html) {
  if (!html) return [];
  const jobs = [];
  const linkPattern = /<a[^>]+href="(https:\/\/www\.linkedin\.com\/comm\/jobs\/view\/\d+[^"]*)"[^>]*>([^<]+)<\/a>/gi;
  let match;
  while ((match = linkPattern.exec(html)) !== null) {
    const url = match[1].replace(/&amp;/g, '&');
    const title = match[2].trim();
    if (!title || title.length < 3) continue;
    const windowStart = match.index + match[0].length;
    const window = html.slice(windowStart, windowStart + 500);
    const companyMatch = window.match(/<(?:span|p)[^>]*>([A-Za-z0-9&.,'\- ]{2,60})<\/(?:span|p)>/);
    const company = companyMatch ? companyMatch[1].trim() : null;
    jobs.push({ title, company, url, source: 'linkedin' });
  }
  const seen = new Set();
  return jobs.filter((j) => {
    if (seen.has(j.url)) return false;
    seen.add(j.url);
    return true;
  });
}

function isLinkedInAlert(sender, subject, html) {
  return /linkedin\.com\/comm\/jobs\/view\//i.test(html || '');
}

function parseWTTJJobs(html) {
  if (!html) return [];
  const jobs = [];
  const linkPattern = /<a[^>]+href="(https:\/\/www\.welcometothejungle\.com\/[a-z]{2}\/companies\/([a-z0-9\-]+)\/jobs\/([a-z0-9\-]+)[^"]*)"[^>]*>([^<]+)<\/a>/gi;
  let match;
  while ((match = linkPattern.exec(html)) !== null) {
    const url = match[1].replace(/&amp;/g, '&');
    const companySlug = match[2];
    const title = match[4].trim();
    if (!title || title.length < 3) continue;
    const company = companySlug
      .split('-')
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
    jobs.push({ title, company, url, source: 'welcometothejungle' });
  }
  const seen = new Set();
  return jobs.filter((j) => {
    if (seen.has(j.url)) return false;
    seen.add(j.url);
    return true;
  });
}

function isWTTJAlert(sender, subject, html) {
  return /welcometothejungle\.com\/[a-z]{2}\/companies\//i.test(html || '');
}

async function insertQueuedJobs(jobs) {
  if (!jobs.length) return { inserted: 0, errors: 0 };
  const rows = jobs.map((j) => ({
    company: j.company || 'Unknown',
    job_title: j.title,
    url: j.url,
    status: 'queued',
    source: j.source,
    created_at: new Date().toISOString(),
  }));
  const { error, count } = await supabase
    .from('applications')
    .upsert(rows, { onConflict: 'url', ignoreDuplicates: true, count: 'exact' });
  if (error) {
    log(`  Supabase insert error: ${error.message}`);
    return { inserted: 0, errors: rows.length };
  }
  return { inserted: count ?? rows.length, errors: 0 };
}

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
    const strippedHtml = body['stripped-html'] || body.strippedHtml || body['body-html'] || '';
    const timestamp = body.timestamp || '';
    const token = body.token || '';
    const signature = body.signature || '';
    log(`Inbound email from=${sender} to=${recipient} subject="${subject.slice(0, 60)}"`);
    if (process.env.MAILGUN_SIGNING_KEY) {
      const valid = verifyMailgunSignature(timestamp, token, signature);
      if (!valid) {
        log('  Signature verification failed — rejecting');
        res.status(401).json({ error: 'Invalid signature' });
        return;
      }
    }
    if (isLinkedInAlert(sender, subject, strippedHtml)) {
      const jobs = parseLinkedInJobs(strippedHtml);
      log(`  LinkedIn alert detected — parsed ${jobs.length} listing(s)`);
      const result = await insertQueuedJobs(jobs);
      res.status(200).json({ status: 'ok', source: 'linkedin', ...result });
      return;
    }
    if (isWTTJAlert(sender, subject, strippedHtml)) {
      const jobs = parseWTTJJobs(strippedHtml);
      log(`  Welcome to the Jungle alert detected — parsed ${jobs.length} listing(s)`);
      const result = await insertQueuedJobs(jobs);
      res.status(200).json({ status: 'ok', source: 'welcometothejungle', ...result });
      return;
    }
    const isGreenhouse = sender.includes('greenhouse-mail.io') || sender.includes('greenhouse.io');
    const isSecurityCodeEmail = /security code/i.test(subject);
    if (!isGreenhouse || !isSecurityCodeEmail) {
      log('  Not a recognized email type — skipping, still 200 OK');
      res.status(200).json({ status: 'ignored', reason: 'unrecognized email type' });
      return;
    }
    const code = extractSecurityCode(strippedText) || extractSecurityCode(bodyPlain);
    if (!code) {
      log('  Could not extract code from email body');
      res.status(200).json({ status: 'no_code_found' });
      return;
    }
    log(`  Extracted code: ${code}`);
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
