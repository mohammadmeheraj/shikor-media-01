import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
export const config = { path: '/api/*' };

const store = () => getStore('shikor-v2');
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...h } });
const SECRET = () => process.env.TOKEN_SECRET || process.env.ADMIN_PASSWORD || '';
const sign = p => crypto.createHmac('sha256', SECRET()).update(p).digest('base64url');
const mkToken = () => { const p = String(Date.now() + 12 * 36e5); return p + '.' + sign(p); }; // 12 ঘণ্টা মেয়াদ
const authed = req => {
  const [p, s] = (req.headers.get('authorization') || '').replace('Bearer ', '').split('.');
  if (!p || !s || !SECRET()) return false;
  const a = Buffer.from(sign(p)), b = Buffer.from(s);
  return a.length === b.length && crypto.timingSafeEqual(a, b) && +p > Date.now();
};
const get = async (k, d) => { try { const v = await store().get(k, { type: 'json' }); return v ?? d; } catch { return d; } };
const put = (k, v) => store().setJSON(k, v);
const day = t => new Date((t || Date.now()) + 216e5).toISOString().slice(0, 10);
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const str = (v, n) => String(v ?? '').slice(0, n);

async function log(a, ip) {
  const l = await get('log', []);
  l.unshift({ t: Date.now(), a, ip });
  await put('log', l.slice(0, 300));
}

// ---- যাচাই (validation)
function cleanPosts(a) {
  if (!Array.isArray(a) || a.length > 3000) throw 0;
  return a.map(p => {
    if (!p || !p.id || !p.title) throw 0;
    return { ...p, id: str(p.id, 40), title: str(p.title, 300), cat: str(p.cat, 30), img: str(p.img, 500), body: str(p.body, 100000),
      seoT: str(p.seoT, 120), seoD: str(p.seoD, 300), status: ['on', 'off', 'draft'].includes(p.status) ? p.status : 'on',
      date: +p.date || Date.now(), exp: +p.exp || 0, pub: +p.pub || 0, top: !!p.top };
  });
}
function cleanAds(a) {
  if (!Array.isArray(a) || a.length > 300) throw 0;
  return a.map(x => {
    if (!x || !x.id || !/^https?:\/\//.test(x.url || '')) throw 0;
    return { ...x, id: str(x.id, 40), name: str(x.name, 100), url: str(x.url, 1000), img: str(x.img, 1000), text: str(x.text, 100), slot: str(x.slot, 20), on: x.on !== false, exp: +x.exp || 0 };
  });
}
function cleanSettings(o) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw 0;
  if (JSON.stringify(o).length > 300000) throw 0;
  return o;
}

// ---- ধীর গতির লগইন সুরক্ষা: ৫ বার ভুল = ১৫ মিনিট বন্ধ
async function login(req, ip) {
  const key = 'rl-' + ip.replace(/[^0-9a-f:.]/gi, '_');
  const r = await get(key, { n: 0, until: 0 });
  if (r.until > Date.now()) return J({ error: 'locked' }, 429);
  let pw = ''; try { pw = (await req.json()).password; } catch {}
  const real = process.env.ADMIN_PASSWORD || '';
  const ok = real.length >= 8 && crypto.timingSafeEqual(sha(pw), sha(real));
  if (!ok) {
    r.n++; if (r.n >= 5) { r.until = Date.now() + 15 * 6e4; r.n = 0; }
    await put(key, r); await log('লগইন ব্যর্থ', ip);
    return J({ error: 'bad' }, r.until > Date.now() ? 429 : 401);
  }
  await store().delete(key).catch(() => {}); await log('লগইন সফল', ip);
  return J({ token: mkToken() });
}

// ---- ট্র্যাকিং (সাধারণ রেট লিমিট সহ)
const hits = new Map();
async function track(req, ip) {
  const w = hits.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - w.t > 6e4) { w.n = 0; w.t = Date.now(); }
  hits.set(ip, w); if (++w.n > 60) return J({ ok: 0 }, 429);
  let b; try { const t = await req.text(); if (t.length > 3000) throw 0; b = JSON.parse(t); } catch { return J({ ok: 0 }, 400); }
  const k = 'stats-' + day(), d = await get(k, { d: day(), pv: 0, uv: 0, p: {}, a: {} });
  const A = id => (d.a[id] = d.a[id] || { i: 0, c: 0 });
  if (b.t === 'view') {
    d.pv++; if (b.u) d.uv++;
    const p = str(b.p, 40); if (p && (d.p[p] || Object.keys(d.p).length < 1000)) d.p[p] = (d.p[p] || 0) + 1;
    (Array.isArray(b.i) ? b.i.slice(0, 5) : []).forEach(id => { id = str(id, 40); if (d.a[id] || Object.keys(d.a).length < 300) A(id).i++; });
  } else if (b.t === 'click') {
    const id = str(b.a, 40); if (id && (d.a[id] || Object.keys(d.a).length < 300)) A(id).c++;
  } else return J({ ok: 0 }, 400);
  await put(k, d); return J({ ok: 1 });
}

export default async (req, ctx) => {
  const ip = ctx?.ip || req.headers.get('x-nf-client-connection-ip') || 'x';
  const u = new URL(req.url), r = u.pathname.replace(/^\/api\/?/, '').replace(/\/$/, ''), m = req.method;
  try {
    if (r === 'login' && m === 'POST') return login(req, ip);
    if (r === 'track' && m === 'POST') return track(req, ip);

    if (r === 'data' && m === 'GET') {
      const all = u.searchParams.get('all') === '1' && authed(req);
      if (u.searchParams.get('all') === '1' && !all) return J({ error: 'auth' }, 401);
      let [posts, ads, settings] = await Promise.all([get('posts', []), get('ads', []), get('settings', {})]);
      if (!all) {
        const n = Date.now();
        posts = posts.filter(p => p.status !== 'draft' && p.status !== 'off' && (!p.pub || p.pub <= n) && (!p.exp || p.exp > n));
        ads = ads.filter(a => a.on !== false && (!a.exp || a.exp > n));
        return J({ posts, ads, settings }, 200, { 'cache-control': 'public, max-age=20, stale-while-revalidate=60' });
      }
      return J({ posts, ads, settings });
    }

    // নিচের সবকিছুতে লগইন লাগবে
    if (!authed(req)) return J({ error: 'auth' }, 401);

    if (r === 'stats' && m === 'GET') {
      const n = Math.min(90, Math.max(1, +u.searchParams.get('days') || 30));
      const ds = Array.from({ length: n }, (_, i) => day(Date.now() - i * 864e5));
      const out = await Promise.all(ds.map(d => get('stats-' + d, null)));
      return J({ days: out.filter(Boolean), at: Date.now() });
    }
    if (r === 'log' && m === 'GET') return J(await get('log', []));
    if (r === 'backup' && m === 'GET') {
      await log('ব্যাকআপ নামানো হয়েছে', ip);
      const [posts, ads, settings] = await Promise.all([get('posts', []), get('ads', []), get('settings', {})]);
      return J({ v: 1, at: Date.now(), posts, ads, settings });
    }
    if (r === 'restore' && m === 'PUT') {
      const b = await req.json();
      const p = cleanPosts(b.posts || []), a = cleanAds(b.ads || []), s = cleanSettings(b.settings || {});
      await Promise.all([put('posts', p), put('ads', a), put('settings', s)]);
      await log(`রিস্টোর: ${p.length} খবর, ${a.length} বিজ্ঞাপন`, ip); return J({ ok: 1 });
    }
    if (m === 'PUT' && ['posts', 'ads', 'settings'].includes(r)) {
      const raw = await req.json();
      const old = await get(r, r === 'settings' ? {} : []);
      const nv = r === 'posts' ? cleanPosts(raw) : r === 'ads' ? cleanAds(raw) : cleanSettings(raw);
      await put(r, nv);
      const name = { posts: 'খবর', ads: 'বিজ্ঞাপন', settings: 'সেটিংস' }[r];
      let msg = name + ' বদলানো হয়েছে';
      if (Array.isArray(nv)) {
        const o = new Set(old.map(x => x.id)), n = new Set(nv.map(x => x.id));
        const add = nv.filter(x => !o.has(x.id)).length, del = old.filter(x => !n.has(x.id)).length;
        msg = `${name}: ${add} নতুন, ${del} মুছেছে, মোট ${nv.length}`;
      }
      await log(msg, ip); return J({ ok: 1 });
    }
    return J({ error: 'not found' }, 404);
  } catch (e) { return J({ error: 'bad request' }, 400); }
};
