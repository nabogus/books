"use strict";
/* ชั้นหนังสือเสียง: the shelf -> a book -> the reader (the clip's sound, its text a page at a time, the line being said
   lit). No server is needed: the data are scripts build.py wrote (data/shelf.js, data/<id>/<key>.js). */

// ---- PURE-BEGIN: no DOM in here (node can run this block)
function clock(t) {
  t = Math.max(0, Math.floor(t || 0));
  const h = Math.floor(t / 3600), m = Math.floor(t / 60) % 60, s = t % 60;
  return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(s).padStart(2, "0");
}
function longTime(secs) {
  const m = Math.max(1, Math.round(secs / 60));
  if (m < 60) return m + " นาที";
  return Math.floor(m / 60) + " ชม." + (m % 60 ? " " + (m % 60) + " นาที" : "");
}
// the stretch of text being said at t: the last one that has started (it stays lit through a pause), -1 before the first
function segAt(segs, t) {
  let lo = 0, hi = segs.length - 1, at = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (segs[mid].t0 <= t + 0.001) { at = mid; lo = mid + 1; } else hi = mid - 1;
  }
  return at;
}
// the page a stretch is on at t; one that runs over a page's end turns the page when the voice gets there
function pageOf(seg, t) {
  const w = seg.where || [];
  if (!w.length) return 0;
  if (w.length === 1 || seg.t1 <= seg.t0) return w[0].pg;
  const f = Math.min(1, Math.max(0, (t - seg.t0) / (seg.t1 - seg.t0)));
  const total = w.reduce((a, x) => a + x.w, 0) || 1;
  let acc = 0;
  for (const x of w) { acc += x.w / total; if (f < acc) return x.pg; }
  return w[w.length - 1].pg;
}
function coverTone(title) {
  let h = 0;
  for (const c of String(title)) h = (h * 31 + c.codePointAt(0)) >>> 0;
  return h % 6;
}
function partName(p) { return p.of > 1 ? p.title + " · ตอนที่ " + p.p : p.title; }
function findVersion(shelf, id) {
  for (const b of (shelf && shelf.books) || []) for (const v of b.versions) if (v.id === id) return { book: b, v };
  return null;
}
function nextRate(r) {
  const all = [0.9, 1, 1.15, 1.3, 1.5];
  return all[(all.indexOf(r) + 1) % all.length] || 1;
}
// -- the locked copy (publish.js wrote it): a box is IV(12) + AES-256-GCM ciphertext and tag
function b64d(s) {
  const b = atob(s), u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
}
function normId(s) { return String(s || "").trim().toLowerCase(); }
async function openBox(key, bytes) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, 12) }, key, bytes.subarray(12)));
}
async function userKey(name, email, salt, iter) {
  const raw = new TextEncoder().encode(normId(name) + "\n" + normId(email));
  const base = await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base,
                                 { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
// what this name and e-mail open in users.json: {k, until}, or null. The boxes carry no name: each is tried.
async function unlock(users, name, email) {
  const key = await userKey(name, email, b64d(users.salt), users.iter);
  for (const box of users.entries || []) {
    try { return JSON.parse(new TextDecoder().decode(await openBox(key, b64d(box)))); } catch (e) { /* not his */ }
  }
  return null;
}
function contentKey(k) { return crypto.subtle.importKey("raw", b64d(k), "AES-GCM", false, ["decrypt"]); }
function dayOf(d) {
  return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
}
function expired(until, today) { return !!until && until < today; }  // his last day is still a day he can use
function thaiDate(ymd) {
  const m = /^(\d{4})-(\d\d)-(\d\d)$/.exec(ymd || "");
  if (!m) return "";
  return +m[3] + " " + ["ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.", "ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค."][+m[2] - 1] + " " + (+m[1] + 543);
}
function untilText(until) { return until ? "ใช้ได้ถึง " + thaiDate(until) : "ใช้ได้ตลอดไป"; }
// -- the admin page (his own machine only)
const NAME_LETTERS = "abcdefghjkmnpqrstuvwxyz23456789";  // no i l o 0 1: read aloud or typed from a chat without mistakes
function randomName(n, pick) {
  let s = "";
  for (let i = 0; i < n; i++) s += NAME_LETTERS[pick(NAME_LETTERS.length)];
  return s;
}
// why this user cannot be saved (Thai, for the page), or "" when he can
function userProblem(u, others) {
  const name = normId(u.name), email = normId(u.email);
  if (!/^[a-z0-9]{4,16}$/.test(name)) return "ชื่อผู้ใช้ต้องเป็นอังกฤษตัวเล็กหรือตัวเลข 4–16 ตัว";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return "อีเมลไม่ถูกรูปแบบ";
  if (u.until && !/^\d{4}-\d\d-\d\d$/.test(u.until)) return "วันหมดอายุไม่ถูกรูปแบบ";
  if ((others || []).some(o => normId(o.name) === name)) return "มีชื่อผู้ใช้นี้อยู่แล้ว";
  return "";
}
function inviteText(url, u) {
  return ["ชั้นหนังสือเสียง", url ? "เปิดที่: " + url : "", "ชื่อผู้ใช้: " + normId(u.name),
          "รหัสผ่าน: อีเมลของคุณ (" + normId(u.email) + ")", untilText(u.until)].filter(Boolean).join("\n");
}
// ---- PURE-END
if (typeof module !== "undefined") module.exports = { clock, longTime, segAt, pageOf, coverTone, partName, findVersion, nextRate,
  b64d, normId, openBox, userKey, unlock, contentKey, dayOf, expired, thaiDate, untilText, NAME_LETTERS, randomName, userProblem, inviteText };

(function () {
  if (typeof document === "undefined") return;
  const $ = (s, el) => (el || document).querySelector(s);
  const app = $("#app");
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const store = {
    get(k, d) { try { const v = localStorage.getItem("bs." + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem("bs." + k, JSON.stringify(v)); } catch (e) { /* private window: nothing kept */ } },
  };
  let SHELF = window.SHELF || { books: [], built: "0" };
  const LOCKED = window.LOCKED || null;  // the published copy: nothing is readable before a login (publish.js)
  let KEY = null, AUTH = null;           // the content key and who is in, when locked
  let ADMIN = null;                      // his own machine: the users and the publish state (serve.py), else null
  const IC = {
    // the gear: Feather's "settings" icon (MIT)
    gear: '<svg viewBox="0 0 24 24" style="fill:none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    user: '<svg viewBox="0 0 24 24"><circle cx="12" cy="8.4" r="3.8"/><path d="M4.4 20.2c.6-4 3.6-6.1 7.6-6.1s7 2.1 7.6 6.1z"/></svg>',
    play: '<svg viewBox="0 0 24 24"><path d="M8.5 5.2v13.6L19.5 12z"/></svg>',
    pause: '<svg viewBox="0 0 24 24"><path d="M7 5h3.6v14H7zM13.4 5H17v14h-3.6z"/></svg>',
    back: '<svg viewBox="0 0 24 24"><path d="M15 5l-7 7 7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    list: '<svg viewBox="0 0 24 24"><path d="M5 7h14M5 12h14M5 17h9" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    moon: '<svg viewBox="0 0 24 24"><path d="M20 14.6A8.2 8.2 0 0 1 9.4 4 7.6 7.6 0 1 0 20 14.6z"/></svg>',
    sun: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.6M12 18.9v2.6M2.5 12h2.6M18.9 12h2.6M5.3 5.3l1.8 1.8M16.9 16.9l1.8 1.8M5.3 18.7l1.8-1.8M16.9 7.1l1.8-1.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    skip: n => '<svg viewBox="0 0 24 24"><g' + (n > 0 ? ' transform="translate(24 0) scale(-1 1)"' : "") +
      '><path d="M12 5.4V2.6L8 5.9l4 3.3V6.9a5.6 5.6 0 1 1-5.6 5.6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></g>' +
      '<text x="12" y="15.4" text-anchor="middle" font-size="6.4" font-weight="700" font-family="Montserrat, sans-serif">10</text></svg>',
  };

  // ---- settings (kept on this device only)
  const S = Object.assign({ size: 20, theme: "", font: "loop", rate: 1 }, store.get("set", {}));
  if (!S.theme) S.theme = window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "night" : "paper";
  function applySettings() {
    const r = document.documentElement;
    r.dataset.theme = S.theme;
    r.dataset.font = S.font;
    r.style.setProperty("--fs", S.size + "px");
    const m = $('meta[name="theme-color"]');
    if (m) m.content = S.theme === "night" ? "#161411" : "#f3ede2";
    store.set("set", S);
  }
  const themeBtn = () => `<button class="ib" data-act="theme" aria-label="สลับพื้นหลัง">${S.theme === "night" ? IC.sun : IC.moon}</button>`;
  const tools = () => `<div class="tools">${ADMIN ? `<a class="ib" href="#/admin" aria-label="จัดการผู้ใช้">${IC.gear}</a>` : ""}${
    LOCKED ? `<button class="ib" data-act="account" aria-label="บัญชีของฉัน">${IC.user}</button>` : ""}${themeBtn()}</div>`;
  const pos = () => store.get("pos", {});
  const done = () => store.get("done", {});

  // ---- the shelf
  function cover(title) {
    return `<div class="cover c${coverTone(title)}"><span class="ct">${esc(title)}</span><span class="cb">หนังสือเสียง</span></div>`;
  }
  function showShelf() {
    document.title = "ชั้นหนังสือเสียง";
    const last = store.get("last"), hit = last && findVersion(SHELF, last.id);
    const lp = hit && hit.v.parts.find(p => p.key === last.key);
    const at = lp ? pos()[last.id + "/" + last.key] || 0 : 0;
    const books = SHELF.books.map(b => {
      const secs = b.versions.reduce((a, v) => a + v.parts.reduce((x, p) => x + p.secs, 0), 0);
      return `<a class="book" href="#/b/${b.versions[0].id}">${cover(b.title)}<div class="bt">${esc(b.title)}</div>
        <div class="bm">${b.versions.map(v => esc(v.label)).join(" · ")}<br>${longTime(secs)}</div></a>`;
    }).join("");
    app.innerHTML = `<div class="wrap">
      <header class="top"><div><h1>ชั้นหนังสือเสียง</h1><p>ฟังไปด้วย อ่านตามไปด้วย</p></div>${tools()}</header>
      ${lp ? `<a class="resume" href="#/b/${last.id}/${last.key}"><span class="go">${IC.play}</span>
        <span><small>ฟังต่อ${at > 5 ? " จาก " + clock(at) : ""}</small><b>${esc(hit.book.title)}</b>
        <small>${esc(hit.v.label)} · ${esc(partName(lp))}</small></span></a>` : ""}
      <p class="label">หนังสือทั้งหมด ${SHELF.books.length} เล่ม</p>
      ${books ? `<div class="grid">${books}</div>`
        : `<div class="empty">ยังไม่มีหนังสือบนชั้น<br>ดับเบิลคลิก “อัปเดตชั้นหนังสือ.bat” เพื่อดึงคลิปที่ทำไว้มา</div>`}
      <p class="foot">${SHELF.at ? "อัปเดตล่าสุด " + esc(SHELF.at) : ""}</p></div>`;
  }

  // ---- a book: its versions and their clips
  function showBook(id) {
    const hit = findVersion(SHELF, id);
    if (!hit) return showShelf();
    const { book, v } = hit, P = pos(), D = done();
    document.title = book.title;
    const total = v.parts.reduce((a, p) => a + p.secs, 0);
    const rows = v.parts.map((p, i) => {
      const k = v.id + "/" + p.key, at = P[k] || 0;
      const st = D[k] ? '<span class="st done">ฟังจบแล้ว</span>' : at > 5 ? `<span class="st">ถึง ${clock(at)}</span>` : "";
      return `<a class="part" href="#/b/${v.id}/${p.key}"><span class="pn">${i + 1}</span>
        <span><b>${esc(partName(p))}</b><small>${clock(p.secs)} นาที</small></span>${st}
        ${!D[k] && at > 5 ? `<i class="bar" style="width:${Math.min(100, at / p.secs * 100).toFixed(1)}%"></i>` : ""}</a>`;
    }).join("");
    app.innerHTML = `<div class="wrap">
      <div class="nav"><a class="ib" href="#/" aria-label="กลับไปชั้นหนังสือ">${IC.back}</a>${themeBtn()}</div>
      <div class="bhead"><div class="book">${cover(book.title)}</div>
        <div><h1>${esc(book.title)}</h1><p>${esc(v.label)} · ${v.parts.length} คลิป · ${longTime(total)}</p></div></div>
      ${book.versions.length > 1 ? `<div class="tabs">${book.versions.map(x =>
        `<a href="#/b/${x.id}" class="${x.id === v.id ? "on" : ""}">${esc(x.label)}</a>`).join("")}</div>` : ""}
      <div class="parts">${rows}</div></div>`;
  }

  // ---- the reader
  let R = null, autoplay = false;
  const cache = {}, waiting = {};
  window.PART_LOADED = d => {
    const k = d.id + "/" + d.key;
    cache[k] = d;
    (waiting[k] || []).forEach(f => f(d));
    delete waiting[k];
  };
  function loadPart(id, key, ver) {
    return new Promise((ok, bad) => {
      const k = id + "/" + key;
      if (cache[k]) return ok(cache[k]);
      if (LOCKED) {
        return fetchBox(`data/${id}/${key}.enc?v=${ver}.${LOCKED.kid}`)
          .then(b => ok(cache[k] = JSON.parse(new TextDecoder().decode(b))), bad);
      }
      (waiting[k] = waiting[k] || []).push(ok);
      const s = document.createElement("script");
      s.src = `data/${id}/${key}.js?v=${ver}`;
      s.onerror = () => bad(new Error("load"));
      document.head.appendChild(s);
    });
  }

  function showReader(id, key) {
    const hit = findVersion(SHELF, id), i = hit ? hit.v.parts.findIndex(p => p.key === key) : -1;
    if (i < 0) return showShelf();
    const { book, v } = hit, part = v.parts[i], next = v.parts[i + 1];
    document.title = partName(part) + " · " + book.title;
    app.innerHTML = `<div class="reader">
      <header class="rbar"><a class="ib" href="#/b/${v.id}" aria-label="กลับไปรายการคลิป">${IC.back}</a>
        <div class="rt"><b>${esc(partName(part))}</b><small>${esc(book.title)} · ${esc(v.label)}</small></div>
        <button class="ib" data-act="toc" aria-label="หัวข้อในคลิปนี้">${IC.list}</button>
        <button class="ib aa" data-act="set" aria-label="ตั้งค่าการอ่าน">Aa</button></header>
      <div class="view" id="view"><div class="pages" id="pages"><p class="wait">กำลังเปิด…</p></div></div>
      <footer class="deck">
        <button class="chip" id="follow" data-act="follow" hidden>↩ กลับไปที่เสียงอ่าน</button>
        <div class="pgrow"><button data-act="prev" id="pprev" aria-label="หน้าก่อน">‹</button><span id="pg">หน้า 1 / 1</span>
          <button data-act="nextpage" id="pnext" aria-label="หน้าถัดไป">›</button></div>
        <input type="range" id="seek" min="0" max="${part.secs}" step="0.1" value="0" aria-label="ตำแหน่งเสียง">
        <div class="times"><span id="tnow">0:00</span><span id="tleft">-${clock(part.secs)}</span></div>
        <div class="ctl"><button class="tx" data-act="rate" id="rate" aria-label="ความเร็ว">${S.rate}×</button>
          <button class="ib" data-act="back" aria-label="ถอย 10 วินาที">${IC.skip(-10)}</button>
          <button class="play" data-act="play" id="play" aria-label="เล่น">${IC.play}</button>
          <button class="ib" data-act="fwd" aria-label="ข้าม 10 วินาที">${IC.skip(10)}</button>
          <button class="tx" data-act="nextpart" aria-label="คลิปถัดไป" ${next ? "" : "disabled"}>ถัดไป ›</button></div>
      </footer>
      <audio id="au" preload="metadata"${LOCKED ? "" : ` src="audio/${v.id}/${part.key}.mp3?v=${part.v}"`}></audio></div>`;
    const au = $("#au");
    R = { id: v.id, key, k: v.id + "/" + key, book, v, part, next, au, segs: [], spans: [], cur: -1, page: 0, pages: 1,
          follow: true, drag: false, saved: 0, timer: 0, data: null, startAt: 0, wantPlay: autoplay, blob: "" };
    autoplay = false;
    const mine = R;
    au.defaultPlaybackRate = au.playbackRate = S.rate;
    const at0 = pos()[R.k] || 0;
    if (at0 > 5 && at0 < part.secs - 8) R.startAt = at0;  // where he stopped: shown at once, sought when the sound is ready
    if (LOCKED) {  // the clip comes as one box: fetched whole, opened, then played from memory
      $("#play").classList.add("busy");
      fetchBox(`audio/${v.id}/${part.key}.enc?v=${part.v}.${LOCKED.kid}`).then(b => {
        if (R !== mine) return;
        R.blob = URL.createObjectURL(new Blob([b], { type: "audio/mpeg" }));
        au.src = R.blob;
        au.defaultPlaybackRate = au.playbackRate = S.rate;
      }).catch(() => {
        if (R !== mine) return;
        $("#play").classList.remove("busy");
        sheet('<div class="endcard"><h2>เปิดเสียงของคลิปนี้ไม่ได้</h2><p>ตรวจอินเทอร์เน็ต แล้วลองเปิดคลิปนี้อีกครั้ง</p></div>');
      });
    }
    store.set("last", { id: v.id, key });
    au.addEventListener("play", onPlayState);
    au.addEventListener("pause", onPlayState);
    au.addEventListener("timeupdate", tick);
    au.addEventListener("seeked", tick);
    au.addEventListener("ended", onEnded);
    au.addEventListener("loadedmetadata", () => {
      if (isFinite(au.duration)) $("#seek").max = au.duration;
      if (R.startAt) { au.currentTime = R.startAt; R.startAt = 0; }
      $("#play").classList.remove("busy");
      if (R.wantPlay) { R.wantPlay = false; au.play().catch(() => {}); }
      tick();
    });
    const seek = $("#seek");
    seek.addEventListener("input", () => { R.drag = true; $("#tnow").textContent = clock(+seek.value); });
    seek.addEventListener("change", () => { R.drag = false; jump(+seek.value, false); });
    const view = $("#view");
    let sx = 0, sy = 0;
    view.addEventListener("touchstart", e => { sx = e.touches[0].clientX; sy = e.touches[0].clientY; }, { passive: true });
    view.addEventListener("touchend", e => {
      const dx = e.changedTouches[0].clientX - sx, dy = e.changedTouches[0].clientY - sy;
      if (Math.abs(dx) > 45 && Math.abs(dx) > 1.5 * Math.abs(dy)) { R.swiped = Date.now(); flip(dx < 0 ? 1 : -1); }
    }, { passive: true });
    view.addEventListener("click", e => {
      const sp = e.target.closest(".s");
      if (!sp || Date.now() - (R.swiped || 0) < 350) return;
      jump(R.segs[+sp.dataset.i].t0, true);
    });
    loadPart(v.id, key, SHELF.built).then(d => {
      if (R !== mine) return;
      R.data = d;
      let n = 0;
      $("#pages").innerHTML = d.paras.map(p => `<p class="k-${p.k}">` + p.s.map(s => {
        R.segs.push({ t0: s[0], t1: s[1] });
        return `<span class="s" data-i="${n++}">${esc(s[2])}</span>`;
      }).join("") + "</p>").join("");
      R.spans = Array.from(document.querySelectorAll("#pages .s"));
      paginate();
      if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { if (R === mine) paginate(); });
    }).catch(() => { if (R === mine) $("#pages").innerHTML = '<p class="wait">เปิดข้อความของคลิปนี้ไม่ได้</p>'; });
    if ("mediaSession" in navigator) {
      try {
        navigator.mediaSession.metadata = new MediaMetadata({ title: partName(part), artist: book.title, album: v.label });
        navigator.mediaSession.setActionHandler("seekbackward", () => jump(au.currentTime - 10, false));
        navigator.mediaSession.setActionHandler("seekforward", () => jump(au.currentTime + 10, false));
        navigator.mediaSession.setActionHandler("nexttrack", next ? () => goNext() : null);
      } catch (e) { /* an older browser */ }
    }
  }

  // the text flows into columns one page wide; a page turn slides the column strip
  function paginate() {
    if (!R || !R.spans.length) return;
    const view = $("#view"), pages = $("#pages");
    const pad = parseFloat(getComputedStyle(view).getPropertyValue("--pad")) || 24;
    const W = Math.max(120, view.clientWidth - 2 * pad);
    R.step = W + 2 * pad;
    pages.style.width = W + "px";
    pages.style.columnWidth = W + "px";
    pages.style.columnGap = 2 * pad + "px";
    R.pages = Math.max(1, Math.round((pages.scrollWidth + 2 * pad) / R.step));
    const base = pages.getBoundingClientRect().left;
    R.spans.forEach((sp, i) => {
      const where = [];
      for (const r of sp.getClientRects()) {
        const pg = Math.max(0, Math.floor((r.left - base + 2) / R.step)), last = where[where.length - 1];
        if (last && last.pg === pg) last.w += r.width; else where.push({ pg, w: r.width });
      }
      R.segs[i].where = where;
    });
    const t = R.startAt || R.au.currentTime, i = segAt(R.segs, t);
    go(R.follow && i >= 0 ? pageOf(R.segs[i], t) : Math.min(R.page, R.pages - 1), true);
    tick();
  }
  function go(n, quiet) {
    n = Math.max(0, Math.min(R.pages - 1, n));
    const pages = $("#pages");
    if (quiet) { pages.style.transition = "none"; }
    pages.style.transform = `translateX(${-n * R.step}px)`;
    if (quiet) { void pages.offsetWidth; pages.style.transition = ""; }
    R.page = n;
    $("#pg").textContent = `หน้า ${n + 1} / ${R.pages}`;
    $("#pprev").disabled = n === 0;
    $("#pnext").disabled = n >= R.pages - 1;
  }
  function flip(d) {
    if (!R) return;
    go(R.page + d);
    const i = R.cur;
    R.follow = i < 0 || pageOf(R.segs[i], R.au.currentTime) === R.page;
    $("#follow").hidden = R.follow;
  }
  function jump(t, play) {
    if (!R) return;
    const dur = isFinite(R.au.duration) ? R.au.duration : R.part.secs;
    t = Math.max(0, Math.min(dur - 0.2, t));
    if (R.au.readyState < 1) { R.startAt = t || 0.01; R.wantPlay = R.wantPlay || play; }  // the sound is not there yet
    else { R.startAt = 0; R.au.currentTime = t; }
    R.follow = true;
    $("#follow").hidden = true;
    if (play && R.au.paused && R.au.readyState >= 1) R.au.play().catch(() => {});
    tick();
  }
  function tick() {
    if (!R || !R.segs.length) return;
    const au = R.au, t = R.startAt || au.currentTime, i = segAt(R.segs, t);
    if (i !== R.cur) {
      if (R.spans[R.cur]) R.spans[R.cur].classList.remove("now");
      if (R.spans[i]) R.spans[i].classList.add("now");
      R.cur = i;
    }
    if (R.follow && i >= 0) {
      const pg = pageOf(R.segs[i], t);
      if (pg !== R.page) go(pg);
    }
    const dur = isFinite(au.duration) ? au.duration : R.part.secs;
    if (!R.drag) { $("#seek").value = t; $("#tnow").textContent = clock(t); }
    $("#tleft").textContent = "-" + clock(dur - t);
    if (!R.startAt && Math.abs(t - R.saved) > 3) savePos();
  }
  function savePos() {
    if (!R || R.startAt) return;  // not sought to where he stopped yet: what is kept stays
    const P = pos();
    P[R.k] = Math.round(R.au.currentTime * 10) / 10;
    R.saved = R.au.currentTime;
    store.set("pos", P);
  }
  function onPlayState() {
    if (!R) return;
    const on = !R.au.paused;
    $("#play").innerHTML = on ? IC.pause : IC.play;
    $("#play").setAttribute("aria-label", on ? "หยุด" : "เล่น");
    clearInterval(R.timer);
    if (on) R.timer = setInterval(tick, 120); else savePos();
  }
  function onEnded() {
    if (!R) return;
    const D = done(), P = pos();
    D[R.k] = 1;
    P[R.k] = 0;
    store.set("done", D);
    store.set("pos", P);
    sheet(`<div class="endcard"><h2>จบคลิปนี้แล้ว</h2>${R.next
      ? `<p>คลิปถัดไป: ${esc(partName(R.next))}</p><button class="big" data-act="nextpart">${IC.play} ฟังคลิปถัดไป</button>`
      : `<p>นี่คือคลิปสุดท้ายที่มีบนชั้นตอนนี้</p><a class="big" href="#/b/${R.id}">กลับไปรายการคลิป</a>`}</div>`);
  }
  function goNext() {
    if (!R || !R.next) return;
    autoplay = true;
    location.hash = `#/b/${R.id}/${R.next.key}`;
  }
  function stopReader() {
    if (!R) return;
    if (R.au.currentTime > 0 && !R.au.ended) savePos();
    clearInterval(R.timer);
    R.au.pause();
    if (R.blob) { R.au.removeAttribute("src"); URL.revokeObjectURL(R.blob); }
    R = null;
    closeSheet();
  }

  // ---- the locked copy: who may come in
  async function fetchBox(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error("HTTP " + r.status);
    return openBox(KEY, new Uint8Array(await r.arrayBuffer()));
  }
  const fetchUsers = () => fetch("users.json?t=" + Date.now(), { cache: "no-store" }).then(r => r.json());
  // "ok", or why not: "" nobody kept on this device, "revoked", "expired", "error" (no network, a broken file)
  async function enter(a, users) {
    try {
      if (!a || !a.name || !a.email) return "";
      if (!a.k || a.kid !== LOCKED.kid || a.ub !== LOCKED.ub) {  // the list or the key changed: is he still on it
        const box = await unlock(users || await fetchUsers(), a.name, a.email);
        if (!box) {  // taken off the list: this device forgets the key it had
          if (a.k) store.set("auth", { name: a.name, email: a.email });
          return "revoked";
        }
        a = { name: normId(a.name), email: normId(a.email), k: box.k, until: box.until, kid: LOCKED.kid, ub: LOCKED.ub };
      }
      if (expired(a.until, dayOf(new Date()))) {
        AUTH = a;
        store.set("auth", { name: a.name, email: a.email });  // past his day: the key is not kept either
        return "expired";
      }
      KEY = await contentKey(a.k);
      SHELF = JSON.parse(new TextDecoder().decode(await fetchBox("data/shelf.enc?t=" + Date.now())));
      AUTH = a;
      store.set("auth", a);
      return "ok";
    } catch (e) { return "error"; }
  }
  const WHY = { revoked: "ชื่อผู้ใช้นี้ใช้ไม่ได้แล้ว ติดต่อเจ้าของชั้นหนังสือ", error: "เปิดชั้นหนังสือไม่ได้ ตรวจอินเทอร์เน็ตแล้วลองอีกครั้ง",
                wrong: "ชื่อผู้ใช้หรืออีเมลไม่ถูก" };
  function showLogin(why) {
    document.title = "ชั้นหนังสือเสียง";
    const a = store.get("auth") || {};
    const msg = why === "expired" ? `สิทธิ์ของคุณหมดอายุเมื่อ ${thaiDate(AUTH && AUTH.until)} ติดต่อเจ้าของชั้นหนังสือ` : WHY[why] || "";
    app.innerHTML = `<div class="gate"><form class="gatecard" id="login" autocomplete="on">
      <div class="emblem">${cover("ชั้นหนังสือเสียง")}</div>
      <h1>ชั้นหนังสือเสียง</h1><p>ใส่ชื่อผู้ใช้และอีเมลที่ได้รับจากเจ้าของชั้นหนังสือ</p>
      <label>ชื่อผู้ใช้<input id="lname" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" value="${esc(a.name || "")}" required></label>
      <label>อีเมล<input id="lemail" name="email" type="email" autocomplete="email" autocapitalize="none" spellcheck="false" value="${esc(a.email || "")}" required></label>
      <button class="big" id="lgo" type="submit">เข้าชั้นหนังสือ</button>
      <p class="err" id="lerr" role="alert">${esc(msg)}</p></form>${themeBtn()}</div>`;
    $("#login").addEventListener("submit", async e => {
      e.preventDefault();
      const btn = $("#lgo");
      btn.disabled = true;
      btn.textContent = "กำลังตรวจ…";
      $("#lerr").textContent = "";
      let res = "error";
      try {
        const users = await fetchUsers();
        res = await enter({ name: $("#lname").value, email: $("#lemail").value }, users);
        if (res === "revoked") res = "wrong";
      } catch (err) { res = "error"; }
      if (res === "ok") return route();
      showLogin(res);
    });
  }
  function accountSheet() {
    if (!AUTH) return;
    sheet(`<h2>บัญชีของฉัน</h2><div class="row"><span>ชื่อผู้ใช้</span><b class="mono">${esc(AUTH.name)}</b></div>
      <div class="row"><span>สิทธิ์</span><span>${esc(untilText(AUTH.until))}</span></div>
      <div class="row"><span>ออกจากเครื่องนี้</span><button class="pill" data-act="logout">ออกจากระบบ</button></div>`);
  }
  function logout() {
    store.set("auth", null);
    KEY = AUTH = null;
    SHELF = { books: [], built: "0" };
    stopReader();
    closeSheet();
    showLogin("");
  }

  // ---- sheets (the reading settings, the clip's headings, the end of a clip)
  function sheet(html) {
    closeSheet();
    document.body.insertAdjacentHTML("beforeend", `<div class="scrim" data-act="close"></div><div class="sheet" role="dialog">${html}</div>`);
  }
  function closeSheet() { document.querySelectorAll(".scrim, .sheet").forEach(x => x.remove()); }
  function settingsSheet() {
    const seg = (name, opts, cur) => `<span class="seg">${opts.map(([v, t]) =>
      `<button data-act="opt" data-name="${name}" data-v="${v}" class="${String(cur) === String(v) ? "on" : ""}">${t}</button>`).join("")}</span>`;
    sheet(`<h2>ตั้งค่าการอ่าน</h2>
      <div class="row"><span>ขนาดตัวหนังสือ</span><span class="seg"><button data-act="size" data-d="-2" aria-label="เล็กลง">A−</button>
        <button class="on" disabled>${S.size}</button><button data-act="size" data-d="2" aria-label="ใหญ่ขึ้น">A+</button></span></div>
      <div class="row"><span>พื้นหลัง</span>${seg("theme", [["paper", "กระดาษ"], ["night", "กลางคืน"]], S.theme)}</div>
      <div class="row"><span>แบบตัวหนังสือ</span>${seg("font", [["loop", "มีหัว"], ["none", "ไม่มีหัว"]], S.font)}</div>`);
  }
  function tocSheet() {
    const toc = (R.data && R.data.toc) || [], t = R.au.currentTime;
    let on = -1;
    toc.forEach((x, i) => { if (x.t <= t + 0.01) on = i; });
    sheet(`<h2>หัวข้อในคลิปนี้</h2><div class="toc">${toc.length ? toc.map((x, i) =>
      `<button data-act="seekto" data-t="${x.t}" class="${x.top ? "" : "sub"} ${i === on ? "on" : ""}"><span>${esc(x.x)}</span>
       <time>${clock(x.t)}</time></button>`).join("") : '<p class="wait">คลิปนี้ไม่มีหัวข้อ</p>'}</div>`);
  }

  // ---- the admin page: only where serve.py runs (his machine). Users are kept in private/users.json there; the
  // published copy gets them when he presses "สร้างชุดเผยแพร่".
  function api(what, body) {
    return fetch("api/admin/" + what, { method: body ? "POST" : "GET", headers: { "X-BookShelf": "admin", "Content-Type": "application/json" },
                                        body: body ? JSON.stringify(body) : undefined })
      .then(async r => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || "HTTP " + r.status); return j; });
  }
  const newName = () => {
    for (;;) {
      const n = randomName(ADMIN.name_len || 6, k => crypto.getRandomValues(new Uint32Array(1))[0] % k);
      if (!ADMIN.users.some(u => u.name === n)) return n;
    }
  };
  function showAdmin(note) {
    document.title = "จัดการผู้ใช้";
    const today = dayOf(new Date()), us = ADMIN.users, p = ADMIN.published;
    const rows = us.map((u, i) => {
      const out = expired(u.until, today);
      return `<div class="urow"><div><b class="mono">${esc(u.name)}</b> <span class="tag ${out ? "bad" : ""}">${out ? "หมดอายุแล้ว (" + thaiDate(u.until) + ")" : esc(untilText(u.until))}</span>
        <small>${esc(u.email)}${u.note ? " · " + esc(u.note) : ""}</small></div>
        <div class="uact"><button class="pill" data-act="invite" data-i="${i}">คัดลอกข้อความเชิญ</button>
        <button class="pill" data-act="until" data-i="${i}">แก้วันหมดอายุ</button>
        <button class="pill warn" data-act="deluser" data-i="${i}">ลบ</button></div></div>`;
    }).join("");
    app.innerHTML = `<div class="wrap admin">
      <div class="nav"><a class="ib" href="#/" aria-label="กลับไปชั้นหนังสือ">${IC.back}</a>${themeBtn()}</div>
      <h1>จัดการผู้ใช้</h1>
      <p class="lead">หน้านี้เปิดได้เฉพาะบนเครื่องนี้ รายชื่อและอีเมลเก็บในเครื่อง ไม่ขึ้นเว็บ</p>
      <section class="card"><h2>เพิ่มผู้ใช้</h2>
        <label>ชื่อผู้ใช้<span class="line"><input id="uname" class="mono" value="${esc(newName())}" autocapitalize="none" spellcheck="false">
          <button class="pill" data-act="reroll" type="button">สุ่มใหม่</button></span></label>
        <label>อีเมล (เขาใช้เป็นรหัสผ่าน)<input id="uemail" type="email" autocapitalize="none" spellcheck="false" placeholder="name@example.com"></label>
        <label>ใช้ได้ถึง<span class="line"><select id="umode"><option value="">ตลอดไป</option><option value="d">ถึงวันที่</option></select>
          <input id="uuntil" type="date" min="${today}" hidden></span></label>
        <label>บันทึกช่วยจำ (เช่น ชื่อเล่น)<input id="unote" maxlength="60"></label>
        <button class="big" data-act="adduser" type="button">เพิ่มผู้ใช้</button><p class="err" id="uerr" role="alert"></p></section>
      <section class="card"><h2>ผู้ใช้ทั้งหมด ${us.length} คน</h2>${rows || '<p class="lead">ยังไม่มีผู้ใช้ เพิ่มตัวคุณเองเป็นคนแรกได้เลย</p>'}</section>
      <section class="card"><h2>เผยแพร่</h2>
        <p class="lead">${p ? `สร้างชุดเผยแพร่ล่าสุด ${esc(p.at)}: ผู้ใช้ ${p.users} คน ${p.clips} คลิป` : "ยังไม่เคยสร้างชุดเผยแพร่"}
          ${ADMIN.dirty ? '<br><b class="hot">มีการแก้ที่ยังไม่อยู่ในชุดเผยแพร่</b>' : ""}</p>
        <label>ที่อยู่เว็บสำหรับเพื่อน (ใส่ในข้อความเชิญ)<input id="uurl" value="${esc(ADMIN.url || "")}" placeholder="https://…" spellcheck="false"></label>
        <div class="line"><button class="big" data-act="publish" type="button">สร้างชุดเผยแพร่</button>
          <button class="pill warn" data-act="rotate" type="button">เปลี่ยนกุญแจทั้งชั้น</button></div>
        <p class="lead" id="pnote">${esc(note || "ชุดเผยแพร่คือโฟลเดอร์ public ในเครื่องนี้ ข้อความและเสียงถูกเข้ารหัส ยังไม่ได้ส่งขึ้นเว็บ")}</p></section></div>`;
    $("#umode").addEventListener("change", e => { $("#uuntil").hidden = !e.target.value; });
    $("#uurl").addEventListener("change", e => saveUsers(ADMIN.users, e.target.value.trim()));
  }
  function saveUsers(users, url, note) {
    return api("users", { users, url: url == null ? ADMIN.url || "" : url }).then(s => { ADMIN = s; showAdmin(note); })
      .catch(e => { const el = $("#uerr"); if (el) el.textContent = String(e.message || e); });
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).catch(() => {});
    const t = document.createElement("textarea");
    t.value = text;
    document.body.appendChild(t);
    t.select();
    try { document.execCommand("copy"); } catch (e) { /* nothing copied */ }
    t.remove();
    return Promise.resolve();
  }
  const ADMIN_ACTS = {
    reroll() { $("#uname").value = newName(); },
    adduser() {
      const u = { name: normId($("#uname").value), email: normId($("#uemail").value),
                  until: $("#umode").value ? $("#uuntil").value || "?" : null, note: $("#unote").value.trim() };
      const bad = userProblem(u, ADMIN.users);
      if (bad) { $("#uerr").textContent = bad; return; }
      saveUsers(ADMIN.users.concat([u]));
    },
    deluser(b) {
      const u = ADMIN.users[+b.dataset.i];
      if (u && confirm(`ลบผู้ใช้ ${u.name} (${u.email})?\nเขาจะเข้าไม่ได้หลังสร้างชุดเผยแพร่ครั้งถัดไป`)) saveUsers(ADMIN.users.filter(x => x !== u));
    },
    until(b) {
      const i = +b.dataset.i, u = ADMIN.users[i];
      sheet(`<h2>${esc(u.name)} ใช้ได้ถึง</h2><div class="row"><span>วันสุดท้ายที่ใช้ได้</span><input id="nuntil" type="date" value="${esc(u.until || "")}"></div>
        <div class="row"><button class="pill" data-act="setuntil" data-i="${i}" data-forever="1">ตลอดไป</button>
        <button class="big" data-act="setuntil" data-i="${i}">บันทึกวันที่</button></div>`);
    },
    setuntil(b) {
      const i = +b.dataset.i, v = b.dataset.forever ? null : $("#nuntil").value;
      if (!b.dataset.forever && !v) return;
      closeSheet();
      saveUsers(ADMIN.users.map((u, k) => (k === i ? Object.assign({}, u, { until: v }) : u)));
    },
    invite(b) {
      const u = ADMIN.users[+b.dataset.i];
      copyText(inviteText(ADMIN.url, u)).then(() => { b.textContent = "คัดลอกแล้ว"; setTimeout(() => { b.textContent = "คัดลอกข้อความเชิญ"; }, 1600); });
    },
    publish(b, rotate) {
      b.disabled = true;
      $("#pnote").textContent = "กำลังเข้ารหัสและสร้างชุดเผยแพร่… (เสียงหลายร้อย MB ใช้เวลาสักครู่)";
      api("publish", { rotate: !!rotate }).then(s => {
        ADMIN = s;
        const r = s.result || {};
        showAdmin(`สร้างแล้ว: ผู้ใช้ ${r.users} คน${r.expired ? " (ตัดคนหมดอายุ " + r.expired + " คน)" : ""} ${r.clips} คลิป · เขียนไฟล์ใหม่ ${r.written} จาก ${r.files} ไฟล์`
                  + (r.rotated ? " · เปลี่ยนกุญแจแล้ว" : "") + " · ยังอยู่ในเครื่อง ยังไม่ได้ส่งขึ้นเว็บ");
      }).catch(e => { b.disabled = false; $("#pnote").textContent = "สร้างไม่ได้: " + String(e.message || e); });
    },
    rotate(b) {
      if (confirm("เปลี่ยนกุญแจทั้งชั้น?\nไฟล์ทุกไฟล์ในชุดเผยแพร่จะถูกเข้ารหัสใหม่ ต้องอัปโหลดเสียงใหม่ทั้งหมด\nคนที่ถูกลบไปแล้วจะเปิดของเก่าไม่ได้อีก ส่วนผู้ใช้ที่ยังอยู่ในรายชื่อเข้าได้ตามเดิม")) ADMIN_ACTS.publish(b, true);
    },
  };

  // ---- one click handler for everything with data-act
  document.addEventListener("click", e => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const act = b.dataset.act;
    if (act === "close") return closeSheet();
    if (act === "theme") { S.theme = S.theme === "night" ? "paper" : "night"; applySettings(); return route(true); }
    if (act === "opt") { S[b.dataset.name] = b.dataset.v; applySettings(); settingsSheet(); return paginate(); }
    if (act === "size") { S.size = Math.max(16, Math.min(30, S.size + +b.dataset.d)); applySettings(); settingsSheet(); return paginate(); }
    if (act === "account") return accountSheet();
    if (act === "logout") return logout();
    if (ADMIN_ACTS[act]) return ADMIN_ACTS[act](b);
    if (!R) return;
    if (act === "play") {
      if (R.au.readyState < 1) { R.wantPlay = !R.wantPlay; b.classList.toggle("armed", R.wantPlay); }  // starts when it is ready
      else if (R.au.paused) { R.follow = true; $("#follow").hidden = true; R.au.play().catch(() => {}); } else R.au.pause();
    }
    else if (act === "back") jump(R.au.currentTime - 10, false);
    else if (act === "fwd") jump(R.au.currentTime + 10, false);
    else if (act === "prev") flip(-1);
    else if (act === "nextpage") flip(1);
    else if (act === "follow") { R.follow = true; $("#follow").hidden = true; tick(); }
    else if (act === "rate") { S.rate = nextRate(S.rate); R.au.playbackRate = S.rate; b.textContent = S.rate + "×"; applySettings(); }
    else if (act === "set") settingsSheet();
    else if (act === "toc") tocSheet();
    else if (act === "seekto") { closeSheet(); jump(+b.dataset.t, true); }
    else if (act === "nextpart") goNext();
  });
  document.addEventListener("keydown", e => {
    if (!R || e.target.matches("input, textarea") || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === " ") { e.preventDefault(); $("#play").click(); }
    else if (e.key === "ArrowRight") flip(1);
    else if (e.key === "ArrowLeft") flip(-1);
    else if (e.key === "Escape") closeSheet();
  });
  let rz = 0;
  window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(paginate, 150); });
  window.addEventListener("pagehide", () => { if (R && R.au.currentTime > 0 && !R.au.ended) savePos(); });

  // ---- routes: #/ the shelf, #/b/<id> a book's version, #/b/<id>/<key> a clip
  let shown = "";
  function route(again) {
    const h = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
    if (again === true && R) return;  // a look changed while reading: the reader stays as it is
    if (again !== true && location.hash === shown && R) return;
    shown = location.hash;
    stopReader();
    window.scrollTo(0, 0);
    if (LOCKED && !KEY) return showLogin("");
    if (h[0] === "admin" && ADMIN) showAdmin();
    else if (h[0] === "b" && h[1] && h[2]) showReader(h[1], h[2]);
    else if (h[0] === "b" && h[1]) showBook(h[1]);
    else showShelf();
  }
  window.addEventListener("hashchange", route);
  applySettings();
  if (LOCKED) {
    app.innerHTML = '<div class="gate"><p class="wait">กำลังเปิดชั้นหนังสือ…</p></div>';
    enter(store.get("auth")).then(res => (res === "ok" ? route() : showLogin(res)));
  } else {
    route();
    if (/^https?:$/.test(location.protocol)) {  // served by serve.py on his own machine: the gear
      api("state").then(s => { ADMIN = s; if (!R) route(true); }).catch(() => {});
    }
  }
})();
