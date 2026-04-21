// workers/worker.js
// ─────────────────────────────────────────────────────────────────────────────
// Camp Allocation — Cloudflare Worker (D1 backend)
// Auth: HMAC-signed session tokens (password never sent after login)
//
// Env secrets required (Cloudflare dashboard → Worker → Settings → Variables):
//   APP_PASSWORD  — the login password
//   TOKEN_SECRET  — random secret for signing tokens (min 32 chars)
//                   generate: crypto.randomUUID()+crypto.randomUUID() in console
// ─────────────────────────────────────────────────────────────────────────────

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,X-Session-Token',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
function err(msg, status = 400) { return json({ error: msg }, status); }

// ── HMAC token helpers ────────────────────────────────────────────────────────
async function signToken(secret, payload) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const data = btoa(JSON.stringify(payload));
  const sig  = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyToken(secret, token) {
  try {
    const [data, sigB64] = token.split('.');
    if (!data || !sigB64) return null;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(data));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function isAuthed(req, env) {
  const token = req.headers.get('X-Session-Token');
  if (!token) return false;
  return (await verifyToken(env.TOKEN_SECRET, token)) !== null;
}

// ── D1 helpers ────────────────────────────────────────────────────────────────
async function getRooms(db) {
  const { results } = await db.prepare('SELECT * FROM rooms ORDER BY id').all();
  return results.map(r => ({ id: r.id, num: r.num, clean: !!r.clean, repair: !!r.repair }));
}

async function getBookings(db) {
  const { results: bRows } = await db.prepare('SELECT * FROM bookings ORDER BY checkin').all();
  const { results: sRows } = await db.prepare('SELECT * FROM booking_segments ORDER BY booking_id, checkin').all();
  const segMap = {};
  sRows.forEach(s => {
    if (!segMap[s.booking_id]) segMap[s.booking_id] = [];
    segMap[s.booking_id].push({ checkin: s.checkin, checkout: s.checkout, isOn: !!s.is_on });
  });
  return bRows.map(b => ({
    id: b.id, roomId: b.room_id, name: b.name,
    company: b.company||'', role: b.role||'',
    checkin: b.checkin, checkout: b.checkout,
    clean: !!b.clean, repair: !!b.repair,
    notes: b.notes||'', color: b.color,
    rosterPattern: b.roster_pattern||'', offweek: b.offweek,
    segments: segMap[b.id] || [],
  }));
}

async function upsertBooking(db, b) {
  await db.prepare(`
    INSERT INTO bookings (id,room_id,name,company,role,checkin,checkout,clean,repair,notes,color,roster_pattern,offweek)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
    ON CONFLICT(id) DO UPDATE SET
      room_id=excluded.room_id, name=excluded.name, company=excluded.company,
      role=excluded.role, checkin=excluded.checkin, checkout=excluded.checkout,
      clean=excluded.clean, repair=excluded.repair, notes=excluded.notes,
      color=excluded.color, roster_pattern=excluded.roster_pattern, offweek=excluded.offweek
  `).bind(b.id,b.roomId,b.name,b.company||'',b.role||'',b.checkin,b.checkout,
          b.clean?1:0,b.repair?1:0,b.notes||'',b.color||0,b.rosterPattern||'',b.offweek||'held').run();
  await db.prepare('DELETE FROM booking_segments WHERE booking_id=?1').bind(b.id).run();
  for (const s of (b.segments||[]))
    await db.prepare('INSERT INTO booking_segments (booking_id,checkin,checkout,is_on) VALUES (?1,?2,?3,?4)')
      .bind(b.id, s.checkin, s.checkout, s.isOn?1:0).run();
}

async function deleteBookingById(db, id) {
  await db.prepare('DELETE FROM booking_segments WHERE booking_id=?1').bind(id).run();
  await db.prepare('DELETE FROM bookings WHERE id=?1').bind(id).run();
}

async function updateRoom(db, r) {
  await db.prepare('UPDATE rooms SET clean=?1, repair=?2 WHERE id=?3')
    .bind(r.clean?1:0, r.repair?1:0, r.id).run();
}

// ── Router ────────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    // POST /api/auth — password in, signed token out
    if (path === '/api/auth' && request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      if (body.password !== env.APP_PASSWORD) return err('Invalid password', 401);
      const token = await signToken(env.TOKEN_SECRET, {
        exp: Date.now() + 8 * 60 * 60 * 1000,   // 8-hour session
      });
      return json({ token });
    }

    // All other routes — must have valid session token
    if (!await isAuthed(request, env)) return err('Unauthorised', 401);

    const db = env.DB;
    try {
      if (path === '/api/rooms' && request.method === 'GET')
        return json(await getRooms(db));

      if (path.match(/^\/api\/rooms\/\d+$/) && request.method === 'PUT') {
        const id = +path.split('/').pop();
        const body = await request.json();
        await updateRoom(db, { id, clean: body.clean, repair: body.repair });
        return json({ ok: true });
      }

      if (path === '/api/bookings' && request.method === 'GET')
        return json(await getBookings(db));

      if (path === '/api/bookings' && request.method === 'POST') {
        const b = await request.json();
        if (!b.id||!b.roomId||!b.name||!b.checkin||!b.checkout) return err('Missing required fields');
        await upsertBooking(db, b);
        return json({ ok: true, id: b.id });
      }

      if (path.match(/^\/api\/bookings\/[^/]+$/) && request.method === 'PUT') {
        const id = decodeURIComponent(path.split('/').pop());
        const b  = await request.json(); b.id = id;
        await upsertBooking(db, b);
        return json({ ok: true });
      }

      if (path.match(/^\/api\/bookings\/[^/]+$/) && request.method === 'DELETE') {
        await deleteBookingById(db, decodeURIComponent(path.split('/').pop()));
        return json({ ok: true });
      }

      if (path === '/api/checkins' && request.method === 'GET') {
        const date = url.searchParams.get('date') || new Date().toISOString().slice(0,10);
        const bks  = await getBookings(db);
        return json(bks.filter(b => b.checkin===date || (b.segments&&b.segments.some(s=>s.checkin===date&&s.isOn))));
      }

      if (path === '/api/checkouts' && request.method === 'GET') {
        const date = url.searchParams.get('date') || new Date().toISOString().slice(0,10);
        const bks  = await getBookings(db);
        return json(bks.filter(b => b.checkout===date || (b.segments&&b.segments.some(s=>s.checkout===date))));
      }

      if (path === '/api/import' && request.method === 'POST') {
        const { bookings: bArr=[], rooms: rArr=[] } = await request.json();
        for (const r of rArr) await updateRoom(db, r);
        for (const b of bArr) await upsertBooking(db, b);
        return json({ ok: true, bookingsImported: bArr.length, roomsImported: rArr.length });
      }

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err('Internal error: ' + e.message, 500);
    }
  },
};
