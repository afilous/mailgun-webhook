/**
 * api/mailgun-inbound.js — Receives Mailgun inbound webhook.
 * Handles THREE email types:
 *   1. Greenhouse security code emails -> writes to `security_codes` table
 *   2. LinkedIn job alert digests      -> parses listings, writes to `applications` (queued)
 *   3. Welcome to the Jungle job alert digests -> same as above
 *
 * Mailgun POSTs inbound email as multipart/form-data with fields:
 *   sender, recipient, subject, body-plain, stripped-text, stripped-html,
 *   timestamp, token, signature (for verification), etc.
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

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------
function verifyMailgunSignature(timestamp, token, signature) {
  const signingKey = process.env.MAILGUN_SIGNING_KEY;
  if (!signingKey) return true;

  const encodedToken = crypto
    .createHmac('sha256', signingKey)
    .update(timestamp + token)
    .digest('hex');

  return encodedToken === signature;
}

// ---------------------------------------------------------------------------
// Greenhouse security code extraction
// ---------------------------------------------------------------------------
function extractSecurityCode(text) {
  if (!text) return null;
  const match = text.match(/security code field on your application:\s*([A-Za-z0-9]{8})/i);
  return match ? match[1] : null;
}

// ---------------------------------------------------------------------------
// LinkedIn job-alert parsing
// ---------------------------------------------------------------------------
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

function isLinkedInAlert(sender, subject) {
  // The sender address alone is a reliable, specific-enough signal --
  // jobalerts-noreply@linkedin.com is never used for anything else.
  // Real LinkedIn alert subjects are actually just "{Top Job Title} at
  // {Company}" (e.g. "Sr. Principal Business Strategy & Planning
  // Consultant at UKG"), which never matches a generic "job alert" phrase
  // -- confirmed from an actual captured email -- so subject is NOT used
  // as part of
