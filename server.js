'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) console.warn('DATABASE_URL eksik. Render Environment Variables içine PostgreSQL bağlantısını ekle.');
if (!JWT_SECRET) console.warn('JWT_SECRET eksik. Render Environment Variables içine güçlü bir gizli anahtar ekle.');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && !DATABASE_URL.includes('localhost') ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000
});

const COUNTRIES = ['Türkiye','Azerbaycan','İtalya','Rusya','İngiltere','Japonya','Amerika'];
const USER_PUBLIC = `id, username, nickname, role, country, sp, money, bank, ammo, health, energy, respect, gold, influence, heat, vip_until, pp_url, airport_country, family_id, banned, ban_until, created_at, updated_at`;

app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: '256kb' }));

function cleanUser(row) {
  if (!row) return null;
  return {
    id: Number(row.id), username: row.username, nickname: row.nickname, role: row.role,
    country: row.country, sp: Number(row.sp), money: Number(row.money), bank: Number(row.bank),
    ammo: Number(row.ammo), health: Number(row.health), energy: Number(row.energy),
    respect: Number(row.respect), gold: Number(row.gold), influence: Number(row.influence),
    heat: Number(row.heat), vipUntil: row.vip_until, pp: row.pp_url || '',
    airportCountry: row.airport_country || null, familyId: row.family_id ? Number(row.family_id) : null,
    banned: !!row.banned, banUntil: row.ban_until
  };
}

function tokenFor(user) {
  if (!JWT_SECRET) throw new Error('Sunucu JWT_SECRET ayarlanmamış.');
  return jwt.sign({ sub: String(user.id) }, JWT_SECRET, { expiresIn: '30d' });
}

async function getUserById(id, client = pool) {
  const r = await client.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

function isBanned(user) {
  if (!user) return false;
  if (!user.banned) return false;
  if (user.ban_until && new Date(user.ban_until).getTime() <= Date.now()) return false;
  return true;
}

async function auth(req, res, next) {
  try {
    const h = req.get('authorization') || '';
    if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'Giriş gerekli.' });
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    const user = await getUserById(payload.sub);
    if (!user) return res.status(401).json({ error: 'Oturum geçersiz.' });
    if (isBanned(user)) return res.status(403).json({ error: 'Hesap yasaklı.' });
    req.user = user;
    next();
  } catch (_) { return res.status(401).json({ error: 'Oturum geçersiz veya süresi dolmuş.' }); }
}

function requireRole(...roles) {
  return (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Bu işlem için yetkin yok.' });
}

async function publicState() {
  const [chat, news, users, airports, families] = await Promise.all([
    pool.query(`SELECT c.id,c.body AS text,c.created_at AS time,u.username,u.nickname,u.role,u.pp_url AS pp FROM chat_messages c JOIN users u ON u.id=c.sender_id WHERE c.deleted_at IS NULL ORDER BY c.id DESC LIMIT 100`),
    pool.query(`SELECT id,title,body AS text,created_at AS time,sender_username AS sender FROM announcements ORDER BY id DESC LIMIT 50`),
    pool.query(`SELECT id,username,nickname,role,country,sp,money,ammo,health,energy,respect,gold,influence,pp_url AS pp FROM users WHERE banned=false ORDER BY sp DESC LIMIT 100`),
    pool.query(`SELECT country,owner_id FROM airports`),
    pool.query(`SELECT id,name,icon,leader_id AS leader,capacity,cash,protection FROM families`)
  ]);
  const airportsObj = {}; airports.rows.forEach(a => airportsObj[a.country] = { country:a.country, owner:a.owner_id ? Number(a.owner_id) : null });
  const familiesObj = {}; families.rows.forEach(f => familiesObj[f.id] = {...f, id:Number(f.id), leader:Number(f.leader), cash:Number(f.cash), protection:Number(f.protection)});
  return {
    chat: chat.rows.reverse(), news: news.rows,
    users: users.rows.map(u=>({...u,id:Number(u.id),sp:Number(u.sp),money:Number(u.money),ammo:Number(u.ammo),health:Number(u.health),energy:Number(u.energy),respect:Number(u.respect),gold:Number(u.gold),influence:Number(u.influence)})),
    airports: airportsObj, families: familiesObj
  };
}

function payload(user, includePublic=false) {
  return includePublic ? { user: cleanUser(user), publicState: null } : { user: cleanUser(user) };
}

app.get(['/','/api','/health','/api/health'], async (req,res) => {
  try { await pool.query('SELECT 1'); res.json({ok:true, service:'KanHanedanı API', database:true}); }
  catch (e) { res.status(503).json({ok:false, service:'KanHanedanı API', database:false}); }
});

async function authRegister(req,res) {
  try {
    let {username,nickname,password} = req.body || {};
    username=String(username||'').trim(); nickname=String(nickname||username).trim(); password=String(password||'');
    if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) return res.status(400).json({error:'Kullanıcı adı 3-20 karakter olmalı.'});
    if (nickname.length < 1 || nickname.length > 30) return res.status(400).json({error:'Takma ad 1-30 karakter olmalı.'});
    if (password.length < 6 || password.length > 128) return res.status(400).json({error:'Şifre 6-128 karakter olmalı.'});
    const hash=await bcrypt.hash(password,12);
    const c=await pool.connect();
    try {
      await c.query('BEGIN');
      const r=await c.query(`INSERT INTO users(username,nickname,password_hash) VALUES($1,$2,$3) RETURNING ${USER_PUBLIC}`,[username,nickname,hash]);
      await c.query('INSERT INTO user_stats(user_id) VALUES($1) ON CONFLICT DO NOTHING',[r.rows[0].id]);
      await c.query('COMMIT');
      res.status(201).json({token:tokenFor(r.rows[0]),user:cleanUser(r.rows[0]),publicState:await publicState()});
    } catch(e) { await c.query('ROLLBACK'); if(e.code==='23505') return res.status(409).json({error:'Bu kullanıcı adı zaten kayıtlı.'}); throw e; }
    finally { c.release(); }
  } catch(e) { console.error(e); res.status(500).json({error:'Kayıt sırasında sunucu hatası.'}); }
}

async function authLogin(req,res) {
  try {
    const username=String(req.body?.username||'').trim(); const password=String(req.body?.password||'');
    const r=await pool.query(`SELECT ${USER_PUBLIC},password_hash FROM users WHERE lower(username)=lower($1)`,[username]);
    const u=r.rows[0];
    if(!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Kullanıcı adı veya şifre hatalı.'});
    if(isBanned(u)) return res.status(403).json({error:'Hesap yasaklı.'});
    await pool.query('UPDATE users SET updated_at=NOW() WHERE id=$1',[u.id]);
    res.json({token:tokenFor(u),user:cleanUser(u),publicState:await publicState()});
  } catch(e) { console.error(e); res.status(500).json({error:'Giriş sırasında sunucu hatası.'}); }
}
app.post(['/auth/register','/api/auth/register'],authRegister);
app.post(['/auth/login','/api/auth/login'],authLogin);

app.get(['/me','/api/me'],auth,async(req,res)=>res.json({user:cleanUser(await getUserById(req.user.id))}));
app.get(['/me/state','/api/me/state'],auth,async(req,res)=>res.json({user:cleanUser(await getUserById(req.user.id))}));
app.put(['/me/state','/api/me/state'],auth,async(req,res)=>{
  try {
    const x=req.body?.user||{}; const nickname=String(x.nickname||req.user.nickname).slice(0,30);
    const pp=String(x.pp||'').slice(0,500000); const country=COUNTRIES.includes(x.country)?x.country:req.user.country;
    const r=await pool.query(`UPDATE users SET nickname=$1,pp_url=$2,country=$3,updated_at=NOW() WHERE id=$4 RETURNING ${USER_PUBLIC}`,[nickname,pp,country,req.user.id]);
    res.json({user:cleanUser(r.rows[0])});
  } catch(e){console.error(e);res.status(500).json({error:'Profil kaydedilemedi.'});}
});
app.get(['/public/state','/api/public/state'],auth,async(req,res)=>res.json({publicState:await publicState()}));

const CRIMES = new Map([
 ['small',['Küçük Soygun',30,800,2400,200000,650000]],['district',['Bölge İşi',30,1000,2600,250000,750000]],['big',['Büyük Vurgun',30,1400,2800,300000,900000]],['organization',['Organizasyon',30,1600,3000,350000,1000000]],['project',['Büyük Proje',60,1800,3000,500000,1200000]],
 ['warehouse',['Depo Operasyonu',30,1200,2800,250000,800000]],['nightdeal',['Gece Anlaşması',30,1400,2900,300000,900000]],['casino',['Yüksek Riskli Baskın',60,1600,3000,400000,1100000]],['artdeal',['Kayıp Eser Anlaşması',60,1800,3000,450000,1200000]],['port',['Liman Vurgunu',60,1800,3000,500000,1300000]],['blackcar',['Gece Konvoyu',60,2000,3000,550000,1400000]],
 ['district2',['İki Bölge Anlaşması',60,2100,3000,600000,1500000]],['network',['Yeraltı Ağı',60,2200,3000,650000,1600000]],['syndicate',['Büyük Ortaklık',60,2300,3000,700000,1700000]],['empire',['İmparatorluk Hamlesi',60,2400,3000,750000,1800000]],
 ['international',['Uluslararası Bağlantı',60,2500,3000,800000,1900000]],['masterplan',['Usta Plan',60,2600,3000,850000,2000000]],['grandjob',['Grand Vurgun',60,2700,3000,900000,2100000]],['kingmaker',['Taht Oyunu',60,2800,3000,950000,2200000]],['finale',['Yeraltı Zirvesi',60,2900,3000,1000000,2500000]],
 ['quick1',['Sokak Teslimatı',30,900,2200,180000,600000]],['quick2',['Gizli Paket',30,1000,2400,200000,650000]],['quick3',['Gece Pazarı İşi',30,1200,2500,250000,700000]],['quick4',['Aracı Buluşması',30,1300,2600,250000,800000]],['quick5',['Depo Sevkiyatı',30,1500,2700,300000,900000]],['quick6',['Kasa Transferi',30,1700,2800,350000,1000000]],['quick7',['Liman Anlaşması',30,1900,2900,400000,1100000]],['quick8',['Şehir Ağı',60,2100,3000,450000,1200000]],['quick9',['Kara Pazar İşi',60,2200,3000,500000,1300000]],['quick10',['Büyük Bağlantı',60,2400,3000,600000,1500000]],['quick11',['Yeraltı Anlaşması',60,2600,3000,700000,1700000]],['quick12',['Büyük Operasyon',60,2800,3000,800000,2000000]]
]);

async function executeCrime(req,res){
  const id=String(req.body?.crimeId||''); const c=CRIMES.get(id);
  if(!c)return res.status(400).json({error:'Geçersiz suç.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const ur=await client.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1 FOR UPDATE`,[req.user.id]); const u=ur.rows[0];
    const cd=await client.query('SELECT available_at FROM crime_cooldowns WHERE user_id=$1 AND crime_id=$2',[u.id,id]);
    if(cd.rows[0] && new Date(cd.rows[0].available_at).getTime()>Date.now()) return await rollbackError(client,res,429,`Bu suç için ${Math.ceil((new Date(cd.rows[0].available_at).getTime()-Date.now())/1000)} saniye beklemelisin.`);
    const [,name,cool,minSp,maxSp,minMoney,maxMoney]=c;
    const roll=Math.random(); const outcome=roll<0.78?'success':roll<0.93?'mid':'failure';
    let sp=0,money=0,ammo=0,health=0;
    if(outcome==='success'){sp=rand(minSp,maxSp);money=rand(minMoney,maxMoney);} else if(outcome==='mid'){sp=rand(Math.floor(minSp*.4),Math.floor(maxSp*.7));money=rand(Math.floor(minMoney*.4),Math.floor(maxMoney*.7));} else {sp=0;money=0;health=-Math.min(15,rand(4,10));}
    const available=new Date(Date.now()+cool*1000);
    await client.query(`INSERT INTO crime_cooldowns(user_id,crime_id,available_at) VALUES($1,$2,$3) ON CONFLICT(user_id,crime_id) DO UPDATE SET available_at=EXCLUDED.available_at`,[u.id,id,available]);
    await client.query(`UPDATE users SET sp=sp+$1,money=money+$2,health=GREATEST(0,health+$3),updated_at=NOW() WHERE id=$4`,[sp,money,health,u.id]);
    await client.query(`INSERT INTO crime_attempts(user_id,crime_id,outcome,sp_delta,money_delta,health_delta) VALUES($1,$2,$3,$4,$5,$6)`,[u.id,id,outcome,sp,money,health]);
    await client.query(`INSERT INTO user_stats(user_id,crimes,operations,total_earned,crime_streak,last_crime_at) VALUES($1,$2,$3,$4,$2,NOW()) ON CONFLICT(user_id) DO UPDATE SET crimes=user_stats.crimes+$2,operations=user_stats.operations+$3,total_earned=user_stats.total_earned+$4,crime_streak=CASE WHEN $2=1 THEN user_stats.crime_streak+1 ELSE user_stats.crime_streak END,last_crime_at=NOW()`,[u.id,1,c[0].includes('project')||c[0].includes('operation')?1:0,money]);
    const nu=await getUserById(u.id,client); await client.query('COMMIT');
    res.json({user:cleanUser(nu),outcome,message:outcome==='success'?`${name} başarılı. +${sp} SP, +${money.toLocaleString('tr-TR')} Para.`:outcome==='mid'?`${name} kısmen başarılı. +${sp} SP, +${money.toLocaleString('tr-TR')} Para.`:`${name} başarısız oldu. SP kaybı yok.`,crimeId:id});
  }catch(e){try{await client.query('ROLLBACK')}catch(_){} console.error(e);res.status(500).json({error:'Suç işlemi sunucuda başarısız.'});}finally{client.release();}
}
function rand(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
async function rollbackError(client,res,status,error){await client.query('ROLLBACK');return res.status(status).json({error});}
app.post(['/crimes/execute','/api/crimes/execute'],auth,executeCrime);

app.post(['/chat','/api/chat'],auth,async(req,res)=>{
  const text=String(req.body?.text||'').trim(); if(!text||text.length>300)return res.status(400).json({error:'Mesaj 1-300 karakter olmalı.'});
  if(Number(req.user.sp)<40000)return res.status(403).json({error:'Chatte konuşmak için en az 40.000 SP gerekir.'});
  await pool.query('INSERT INTO chat_messages(sender_id,body) VALUES($1,$2)',[req.user.id,text]);
  res.json({user:cleanUser(await getUserById(req.user.id)),publicState:await publicState()});
});

app.post(['/travel/start','/api/travel/start'],auth,async(req,res)=>{
  const country=String(req.body?.country||''); if(!COUNTRIES.includes(country))return res.status(400).json({error:'Geçersiz ülke.'});
  if(country===req.user.country)return res.status(400).json({error:'Zaten bu ülkedesin.'});
  const planeId=String(req.body?.planeId||'');
  const vip=req.user.vip_until && new Date(req.user.vip_until)>new Date();
  const minutes=vip?1:(planeId==='fokker'?20:planeId==='boeing777'?15:planeId==='lv-azf'?12:planeId==='pr-goc'?11.5:planeId==='f-hsun'?10:0);
  if(!vip && minutes<=0)return res.status(400).json({error:'Geçerli bir uçak seçmelisin.'});
  const until=new Date(Date.now()+minutes*60000);
  const r=await pool.query(`UPDATE users SET country=$1,airport_country=$1,updated_at=NOW() WHERE id=$2 RETURNING ${USER_PUBLIC}`,[country,req.user.id]);
  await pool.query(`INSERT INTO travel_orders(user_id,from_country,to_country,plane_id,starts_at,arrives_at,status) VALUES($1,$2,$3,$4,NOW(),$5,'completed')`,[req.user.id,req.user.country,country,planeId,until]);
  res.json({user:cleanUser(r.rows[0]),publicState:await publicState()});
});

app.post(['/shop/buy','/api/shop/buy'],auth,async(req,res)=>{
  const category=String(req.body?.category||''), id=String(req.body?.id||'');
  // Client only sends an item identifier. Price/ownership is validated here.
  const prices={protection:{vest:7500000000000,armored_vehicle:10000000000000,underground_depot:12500000000000},weapons:{}};
  const price=prices[category]?.[id]; if(price==null)return res.status(400).json({error:'Bu mağaza ürünü backend kataloğunda yok.'});
  const c=await pool.connect(); try{await c.query('BEGIN');const r=await c.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1 FOR UPDATE`,[req.user.id]);const u=r.rows[0];if(Number(u.money)<price)return rollbackError(c,res,400,'Yeterli paran yok.');await c.query('UPDATE users SET money=money-$1,updated_at=NOW() WHERE id=$2',[price,u.id]);await c.query('INSERT INTO inventory_items(user_id,category,item_id,quantity) VALUES($1,$2,$3,1) ON CONFLICT(user_id,category,item_id) DO UPDATE SET quantity=inventory_items.quantity+1',[u.id,category,id]);const nu=await getUserById(u.id,c);await c.query('COMMIT');res.json({user:cleanUser(nu)});}catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Satın alma başarısız.'});}finally{c.release();}
});

app.get(['/trade/state','/api/trade/state'],auth,async(req,res)=>{
  const seed=Math.floor(Date.now()/150000); const rnd=(n)=>{let x=Math.sin(seed+n)*10000;return x-Math.floor(x)};
  const make=(base)=>Array.from({length:3},(_,i)=>Array.from({length:7},(_,j)=>Math.floor(base*(0.75+rnd(i*11+j)*0.5))));
  res.json({prices:{weapon:make(500000),tech:make(800000)}});
});

app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'Beklenmeyen sunucu hatası.'});});

pool.query('SELECT 1').then(()=>app.listen(PORT,()=>console.log(`KanHanedanı API listening on ${PORT}`))).catch(e=>{console.error('PostgreSQL bağlantısı kurulamadı:',e.message);process.exit(1);});
