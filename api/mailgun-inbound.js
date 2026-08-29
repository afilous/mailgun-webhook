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
 * the subject -- confirmed from a real captured forward.
 *
 * PARSING NOTE (LinkedIn): title + URL come from the anchor with a
 * "font-bold" class (the visible job title link). Company + location come
 * from the "text-system-gray-100" <p> tag directly under each title --
 * both confirmed stable against a real captured LinkedIn alert email.
 * Titles and company lines appear in matching order, one pair per job
 * card, so they're zipped by index rather than searched via a text
 * window (an earlier version tried a window-based approach and a
 * character-class that excluded parentheses, which silently failed on
 * every listing since real company lines look like "Ladders · United
 * States (Remote)").
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

  const titlePattern = /<a[^>]+href="(https:\/\/www\.linkedin\.com\/comm\/jobs\/view\/\d+[^"]*)"[^>]*class="[^"]*font-bold[^"]*"[^>]*>\s*([^<]+?)\s*<\/a>/gi;
  const companyPattern = /<p[^>]*class="[^"]*text-system-gray-100[^"]*"[^>]*>\s*([^<]+?)\s*<\/p>/gi;

  const titles = [];
  let m;
  while ((m = titlePattern.exec(html)) !== null) {
    titles.push({ url: m[1].replace(/&amp;/g, '&'), title: m[2].trim() });
  }

  const companies = [];
  while ((m = companyPattern.exec(html)) !== null) {
    companies.push(m[1].trim());
  }

  const jobs = titles.map((t, i) => {
    const raw = companies[i] || '';
    const parts = raw.split(/\s*(?:&middot;|·)\s*/);
    const company = parts[0] || null;
    return { title: t.title, company, url: t.url, source: 'linkedin' };
  });

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
