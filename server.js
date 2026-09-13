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
const INITIAL_OWNER_USERNAME = String(process.env.INITIAL_OWNER_USERNAME || '').trim();

if (!DATABASE_URL) throw new Error('DATABASE_URL eksik.');
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET eksik veya çok kısa (en az 32 karakter).');

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
app.use(cors({ origin: true, credentials: false, methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '256kb', strict: true }));

// Basit bellek içi hız sınırlama: brute-force ve spam saldırılarını azaltır.
const rateBuckets = new Map();
function rateLimit({windowMs=60000,max=60,keyPrefix='global'}={}) {
  return (req,res,next)=>{
    const key=keyPrefix+':' + (req.ip||req.socket.remoteAddress||'unknown');
    const now=Date.now(); let b=rateBuckets.get(key);
    if(!b || now-b.start>=windowMs) b={start:now,count:0};
    b.count++; rateBuckets.set(key,b);
    if(b.count>max){ res.set('Retry-After',String(Math.max(1,Math.ceil((b.start+windowMs-now)/1000)))); return res.status(429).json({error:'Çok fazla istek. Biraz bekleyip tekrar dene.'}); }
    next();
  };
}
setInterval(()=>{const now=Date.now(); for(const [k,b] of rateBuckets) if(now-b.start>300000) rateBuckets.delete(k);},300000).unref();
const authRate=rateLimit({windowMs:60000,max:12,keyPrefix:'auth'});
const writeRate=rateLimit({windowMs:10000,max:30,keyPrefix:'write'});
app.use((req,res,next)=>{ if(['POST','PUT','PATCH','DELETE'].includes(req.method)) return writeRate(req,res,next); next(); });

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
    pool.query(`SELECT a.id,a.title,a.body AS text,a.created_at AS time,u.username AS sender,u.nickname AS author FROM announcements a JOIN users u ON u.id=a.author_id ORDER BY a.id DESC LIMIT 50`),
    pool.query(`SELECT id,username,nickname,role,country,sp,money,ammo,health,energy,respect,gold,influence,pp_url AS pp FROM users WHERE banned=false ORDER BY sp DESC LIMIT 100`),
    pool.query(`SELECT country,owner_id FROM airports`),
    pool.query(`SELECT id,name,icon,leader_id AS leader,capacity,cash,protection,factories,leave_cost,total_income,last_income FROM families`)
  ]);
  const airportsObj = {}; airports.rows.forEach(a => airportsObj[a.country] = { country:a.country, owner:a.owner_id ? Number(a.owner_id) : null });
  const familiesObj = {}; families.rows.forEach(f => familiesObj[f.id] = {...f, id:Number(f.id), leader:Number(f.leader), cash:Number(f.cash), protection:Number(f.protection), factories:Array.isArray(f.factories)?f.factories:[], leaveCost:Number(f.leave_cost||0), totalIncome:Number(f.total_income||0)});
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
      if(INITIAL_OWNER_USERNAME && username.toLowerCase()===INITIAL_OWNER_USERNAME.toLowerCase()){ await c.query(`UPDATE users SET role='owner' WHERE id=$1`,[r.rows[0].id]); r.rows[0].role='owner'; }
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
app.post(['/auth/register','/api/auth/register'],authRate,authRegister);
app.post(['/auth/login','/api/auth/login'],authRate,authLogin);

app.get(['/me','/api/me'],auth,async(req,res)=>res.json({user:cleanUser(await getUserById(req.user.id))}));
app.get(['/me/state','/api/me/state'],auth,async(req,res)=>res.json({user:cleanUser(await getUserById(req.user.id))}));
app.put(['/me/state','/api/me/state'],auth,async(req,res)=>{
  try {
    const x=req.body?.user||{}; const nickname=String(x.nickname||req.user.nickname).slice(0,30);
    const pp=String(x.pp||'').trim();
    if(pp.length>2048 || (pp && !/^https?:\/\//i.test(pp))) return res.status(400).json({error:'Profil fotoğrafı yalnızca http/https bağlantısı olabilir ve 2048 karakteri geçemez.'});
    const r=await pool.query(`UPDATE users SET nickname=$1,pp_url=$2,updated_at=NOW() WHERE id=$3 RETURNING ${USER_PUBLIC}`,[nickname,pp,req.user.id]);
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
    const [name,cool,minSp,maxSp,minMoney,maxMoney]=c;
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
async function ensureCrimeDefinitions(){
  for(const [id,c] of CRIMES){await pool.query(`INSERT INTO crime_definitions(id,name,description,category,cooldown_seconds,min_sp,max_sp,min_money,max_money) VALUES($1,$2,$3,'crime',$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,cooldown_seconds=EXCLUDED.cooldown_seconds,min_sp=EXCLUDED.min_sp,max_sp=EXCLUDED.max_sp,min_money=EXCLUDED.min_money,max_money=EXCLUDED.max_money,active=true`,[id,c[0],c[0]+' operasyonu',c[1],c[2],c[3],c[4],c[5]]);}
}

app.post(['/crimes/execute','/api/crimes/execute'],auth,executeCrime);

app.post(['/chat','/api/chat'],auth,async(req,res)=>{
  const text=String(req.body?.text||'').trim(); if(!text||text.length>300)return res.status(400).json({error:'Mesaj 1-300 karakter olmalı.'});
  if(Number(req.user.sp)<40000)return res.status(403).json({error:'Chatte konuşmak için en az 40.000 SP gerekir.'});
  await pool.query('INSERT INTO chat_messages(sender_id,body) VALUES($1,$2)',[req.user.id,text]);
  res.json({user:cleanUser(await getUserById(req.user.id)),publicState:await publicState()});
});

app.post(['/travel/start','/api/travel/start'],auth,async(req,res)=>{
  try{
    const country=String(req.body?.country||''); if(!COUNTRIES.includes(country))return res.status(400).json({error:'Geçersiz ülke.'});
    const planeId=String(req.body?.planeId||'');
    const c=await pool.connect();
    try{
      await c.query('BEGIN');
      const ur=await c.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1 FOR UPDATE`,[req.user.id]); const u=ur.rows[0];
      if(country===u.country)return rollbackError(c,res,400,'Zaten bu ülkedesin.');
      const vip=u.vip_until && new Date(u.vip_until)>new Date();
      const planes={fokker:{minutes:20,cost:500000},boeing777:{minutes:15,cost:1000000},'lv-azf':{minutes:12,cost:1500000},'pr-goc':{minutes:11.5,cost:2000000},'f-hsun':{minutes:10,cost:2500000}};
      const plane=planes[planeId];
      if(!vip && !plane)return rollbackError(c,res,400,'Geçerli bir uçağın olmalı.');
      const minutes=vip?1:plane.minutes, cost=vip?0:plane.cost;
      if(!vip && Number(u.money)<cost)return rollbackError(c,res,400,'Uçuş için yeterli paran yok.');
      const until=new Date(Date.now()+minutes*60000);
      if(!vip) await c.query('UPDATE users SET money=money-$1,updated_at=NOW() WHERE id=$2',[cost,u.id]);
      await c.query(`UPDATE users SET country=$1,airport_country=$1,updated_at=NOW() WHERE id=$2`,[country,u.id]);
      await c.query(`UPDATE travel_orders SET status='completed' WHERE user_id=$1 AND status='active'`,[u.id]);
      await c.query(`INSERT INTO travel_orders(user_id,destination_country,plane_id,started_at,arrives_at,status) VALUES($1,$2,$3,NOW(),$4,'completed')`,[u.id,country,planeId||'vip',until]);
      const nu=await getUserById(u.id,c); await c.query('COMMIT');
      res.json({user:cleanUser(nu),publicState:await publicState()});
    }catch(e){try{await c.query('ROLLBACK')}catch(_){} throw e}finally{c.release()}
  }catch(e){console.error(e);res.status(500).json({error:'Seyahat işlemi sunucuda başarısız.'});}
});

app.post(['/shop/buy','/api/shop/buy'],auth,async(req,res)=>{
  const category=String(req.body?.category||''), id=String(req.body?.id||'');
  const catalog={
    protection:{vest:7500000,armored_vehicle:10000000,underground_depot:12500000},
    weapons:{}, planes:{fokker:500000,boeing777:1000000,'lv-azf':1500000,'pr-goc':2000000,'f-hsun':2500000}
  };
  const price=catalog[category]?.[id]; if(price==null)return res.status(400).json({error:'Bu mağaza ürünü backend kataloğunda yok.'});
  const itemKey=`${category}:${id}`; const c=await pool.connect();
  try{await c.query('BEGIN');const r=await c.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1 FOR UPDATE`,[req.user.id]);const u=r.rows[0];
    const inv=await c.query('SELECT quantity FROM inventory_items WHERE user_id=$1 AND item_key=$2',[u.id,itemKey]);
    if(Number(inv.rows[0]?.quantity||0)>0)return rollbackError(c,res,400,'Bu eşyaya zaten sahipsin.');
    if(Number(u.money)<price)return rollbackError(c,res,400,'Yeterli paran yok.');
    await c.query('UPDATE users SET money=money-$1,updated_at=NOW() WHERE id=$2',[price,u.id]);
    await c.query(`INSERT INTO inventory_items(user_id,item_key,quantity) VALUES($1,$2,1) ON CONFLICT(user_id,item_key) DO UPDATE SET quantity=inventory_items.quantity+1`,[u.id,itemKey]);
    const nu=await getUserById(u.id,c);await c.query('COMMIT');res.json({user:cleanUser(nu)});
  }catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Satın alma başarısız.'});}finally{c.release();}
});

app.get(['/admin/users','/api/admin/users'],auth,requireRole('owner','fakeOwner'),async(req,res)=>{
  const r=await pool.query(`SELECT ${USER_PUBLIC} FROM users ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'fakeOwner' THEN 1 WHEN 'admin' THEN 2 ELSE 3 END, username`);
  res.json({users:r.rows.map(cleanUser)});
});
app.patch(['/admin/users/:id','/api/admin/users/:id'],auth,requireRole('owner','fakeOwner'),async(req,res)=>{
  const targetId=Number(req.params.id); if(!Number.isInteger(targetId))return res.status(400).json({error:'Geçersiz oyuncu.'});
  const x=req.body||{}; const c=await pool.connect();
  try{await c.query('BEGIN');
    const tr=await c.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1 FOR UPDATE`,[targetId]); const t=tr.rows[0]; if(!t)return rollbackError(c,res,404,'Oyuncu bulunamadı.');
    if(req.user.role==='fakeOwner' && (targetId===req.user.id || t.role==='owner'))return rollbackError(c,res,403,'Bu hesabı yönetme yetkin yok.');
    const vals={money:Math.max(0,Math.floor(Number(x.money??t.money))),bank:Math.max(0,Math.floor(Number(x.bank??t.bank))),sp:Math.max(0,Math.floor(Number(x.sp??t.sp))),ammo:Math.max(0,Math.floor(Number(x.ammo??t.ammo))),health:Math.min(100,Math.max(0,Math.floor(Number(x.health??t.health)))),energy:Math.min(100,Math.max(0,Math.floor(Number(x.energy??t.energy)))),respect:Math.max(0,Math.floor(Number(x.respect??t.respect))),country:COUNTRIES.includes(x.country)?x.country:t.country};
    if(req.user.role==='fakeOwner'){
      for(const k of ['money','bank','sp','ammo','health','energy','respect']) if(vals[k]>Number(t[k])) return rollbackError(c,res,403,'Normal Owner yalnızca değer düşürebilir.');
    }
    const r=await c.query(`UPDATE users SET money=$1,bank=$2,sp=$3,ammo=$4,health=$5,energy=$6,respect=$7,country=$8,airport_country=$8,updated_at=NOW() WHERE id=$9 RETURNING ${USER_PUBLIC}`,[vals.money,vals.bank,vals.sp,vals.ammo,vals.health,vals.energy,vals.respect,vals.country,targetId]);
    await c.query(`INSERT INTO admin_logs(actor_user_id,target_user_id,action,details) VALUES($1,$2,'update_user',$3)`,[req.user.id,targetId,JSON.stringify(vals)]);
    await c.query('COMMIT');res.json({user:cleanUser(r.rows[0]),publicState:await publicState()});
  }catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Yönetim işlemi başarısız.'});}finally{c.release();}
});
app.post(['/admin/announcements','/api/admin/announcements'],auth,requireRole('owner'),async(req,res)=>{
  const title=String(req.body?.title||'').trim(),body=String(req.body?.body||'').trim();if(!title||!body)return res.status(400).json({error:'Başlık ve duyuru metni gerekli.'});
  const r=await pool.query(`INSERT INTO announcements(author_id,title,body) VALUES($1,$2,$3) RETURNING id,title,body AS text,created_at AS time`,[req.user.id,title,body]);res.json({announcement:r.rows[0],publicState:await publicState()});
});
app.delete(['/admin/chat/:id','/api/admin/chat/:id'],auth,requireRole('owner','fakeOwner'),async(req,res)=>{const id=Number(req.params.id);if(!Number.isInteger(id))return res.status(400).json({error:'Geçersiz mesaj.'});await pool.query('UPDATE chat_messages SET deleted_at=NOW() WHERE id=$1',[id]);res.json({publicState:await publicState()});});

app.get(['/trade/state','/api/trade/state'],auth,async(req,res)=>{
  const seed=Math.floor(Date.now()/150000); const rnd=(n)=>{let x=Math.sin(seed+n)*10000;return x-Math.floor(x)};
  const make=(base)=>Array.from({length:3},(_,i)=>Array.from({length:7},(_,j)=>Math.floor(base*(0.75+rnd(i*11+j)*0.5))));
  res.json({prices:{weapon:make(500000),tech:make(800000)}});
});



function finiteInt(v, min=0, max=Number.MAX_SAFE_INTEGER){
  const n=Number(v); if(!Number.isFinite(n) || !Number.isInteger(n) || n<min || n>max) return null; return n;
}
function textField(v,max=300){ const t=String(v??'').trim(); return t && t.length<=max ? t : null; }

// Runtime migrations for fields needed by the existing online UI. Safe to run on every deploy.
async function ensureOnlineSchema(){
  await pool.query(`ALTER TABLE families ADD COLUMN IF NOT EXISTS factories JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await pool.query(`ALTER TABLE families ADD COLUMN IF NOT EXISTS leave_cost NUMERIC(30,0) NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE families ADD COLUMN IF NOT EXISTS total_income NUMERIC(30,0) NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE families ADD COLUMN IF NOT EXISTS last_income TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_support_user_status ON support_tickets(user_id,status,created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_family_messages_time ON family_messages(family_id,created_at DESC)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_dm_members_user ON dm_members(user_id,thread_id)`);
}

async function bootstrapOwner(){
  if(!INITIAL_OWNER_USERNAME) return;
  await pool.query(`UPDATE users SET role='owner',updated_at=NOW() WHERE lower(username)=lower($1)`,[INITIAL_OWNER_USERNAME]);
}

app.get(['/rankings','/api/rankings'],auth,async(req,res)=>{
  const type=String(req.query.type||'sp');
  const map={sp:'sp',money:'money',wealth:'money',ammo:'ammo',respect:'respect',actions:'influence',gold:'gold',influence:'influence'};
  const col=map[type]||'sp';
  const r=await pool.query(`SELECT username,nickname,role,country,${col} AS value,pp_url AS pp FROM users WHERE banned=false ORDER BY ${col} DESC,id ASC LIMIT 100`);
  res.json({type,rows:r.rows.map(x=>({...x,value:Number(x.value||0)}))});
});

app.post(['/transfer','/api/transfer'],auth,async(req,res)=>{
  try{
    const target=String(req.body?.username||'').trim(); const kind=String(req.body?.kind||''); const amount=finiteInt(req.body?.amount,1,10**15);
    if(!target || !['money','ammo'].includes(kind) || amount===null) return res.status(400).json({error:'Geçersiz transfer.'});
    const min=kind==='money'?1000000:50000, max=kind==='money'?1000000000000:500000;
    if(amount<min||amount>max)return res.status(400).json({error:`Miktar ${min.toLocaleString('tr-TR')} ile ${max.toLocaleString('tr-TR')} arasında olmalı.`});
    const c=await pool.connect();
    try{ await c.query('BEGIN');
      const sr=await c.query(`SELECT id,username,nickname,${kind} FROM users WHERE lower(username)=lower($1) AND banned=false FOR UPDATE`,[target]);
      const rr=sr.rows[0]; if(!rr||Number(rr.id)===Number(req.user.id)) return rollbackError(c,res,400,'Geçerli bir oyuncu seç.');
      const ur=await c.query(`SELECT id,${kind} FROM users WHERE id=$1 FOR UPDATE`,[req.user.id]);
      if(Number(ur.rows[0][kind])<amount)return rollbackError(c,res,400,'Yeterli kaynak yok.');
      await c.query(`UPDATE users SET ${kind}=${kind}-$1,updated_at=NOW() WHERE id=$2`,[amount,req.user.id]);
      await c.query(`UPDATE users SET ${kind}=${kind}+$1,updated_at=NOW() WHERE id=$2`,[amount,rr.id]);
      await c.query(`INSERT INTO notifications(user_id,body) VALUES($1,$2)`,[rr.id,`${req.user.nickname} sana ${amount.toLocaleString('tr-TR')} ${kind==='money'?'para':'mermi'} gönderdi.`]);
      await c.query(`INSERT INTO admin_logs(actor_user_id,target_user_id,action,details) VALUES($1,$2,'transfer',$3)`,[req.user.id,rr.id,JSON.stringify({kind,amount})]);
      const nu=await getUserById(req.user.id,c); await c.query('COMMIT'); res.json({user:cleanUser(nu),publicState:await publicState()});
    }catch(e){try{await c.query('ROLLBACK')}catch(_){} throw e}finally{c.release()}
  }catch(e){console.error(e);res.status(500).json({error:'Transfer başarısız.'});}
});

app.get(['/notifications','/api/notifications'],auth,async(req,res)=>{
  const r=await pool.query(`SELECT id,body AS text,is_read AS read,created_at AS time FROM notifications WHERE user_id=$1 ORDER BY id DESC LIMIT 100`,[req.user.id]);
  await pool.query(`UPDATE notifications SET is_read=true WHERE user_id=$1`,[req.user.id]);
  res.json({notifications:r.rows});
});

app.get(['/dm','/api/dm'],auth,async(req,res)=>{
  const r=await pool.query(`SELECT m.id,m.body AS text,m.created_at AS time,u.username AS sender,u.nickname AS sender_nickname FROM dm_messages m JOIN dm_members mine ON mine.thread_id=m.thread_id AND mine.user_id=$1 JOIN users u ON u.id=m.sender_id WHERE m.deleted_at IS NULL ORDER BY m.id DESC LIMIT 200`,[req.user.id]);
  res.json({dms:r.rows});
});
app.post(['/dm','/api/dm'],auth,async(req,res)=>{
  const target=String(req.body?.username||'').trim(); const text=textField(req.body?.text,300);
  if(!target||!text)return res.status(400).json({error:'Alıcı ve mesaj gerekli.'});
  const c=await pool.connect(); try{await c.query('BEGIN');
    const tr=await c.query(`SELECT id FROM users WHERE lower(username)=lower($1) AND banned=false`,[target]); const t=tr.rows[0]; if(!t||Number(t.id)===Number(req.user.id))return rollbackError(c,res,400,'Geçersiz alıcı.');
    let th=await c.query(`SELECT dm_threads.id FROM dm_threads JOIN dm_members a ON a.thread_id=dm_threads.id AND a.user_id=$1 JOIN dm_members b ON b.thread_id=dm_threads.id AND b.user_id=$2 LIMIT 1`,[req.user.id,t.id]);
    let tid=th.rows[0]?.id; if(!tid){tid=(await c.query(`INSERT INTO dm_threads DEFAULT VALUES RETURNING id`)).rows[0].id; await c.query(`INSERT INTO dm_members(thread_id,user_id) VALUES($1,$2),($1,$3)`,[tid,req.user.id,t.id]);}
    await c.query(`INSERT INTO dm_messages(thread_id,sender_id,body) VALUES($1,$2,$3)`,[tid,req.user.id,text]);
    await c.query(`INSERT INTO notifications(user_id,body) VALUES($1,$2)`,[t.id,`${req.user.nickname} sana bir DM gönderdi.`]);
    await c.query('COMMIT'); res.json({user:cleanUser(await getUserById(req.user.id)),dms:(await pool.query(`SELECT m.id,m.body AS text,m.created_at AS time,u.username AS sender,u.nickname AS sender_nickname FROM dm_messages m JOIN dm_members mine ON mine.thread_id=m.thread_id AND mine.user_id=$1 JOIN users u ON u.id=m.sender_id WHERE m.deleted_at IS NULL ORDER BY m.id DESC LIMIT 200`,[req.user.id])).rows});
  }catch(e){try{await c.query('ROLLBACK')}catch(_){} console.error(e);res.status(500).json({error:'DM gönderilemedi.'});}finally{c.release()}
});

app.get(['/support','/api/support'],auth,async(req,res)=>{
  const isStaff=['owner','fakeOwner','admin'].includes(req.user.role);
  const q=isStaff?`SELECT t.*,u.username FROM support_tickets t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 200`:`SELECT * FROM support_tickets WHERE user_id=$1 ORDER BY id DESC LIMIT 50`;
  const r=await pool.query(q,isStaff?[]:[req.user.id]);
  const ids=r.rows.map(x=>x.id); let replies=[]; if(ids.length) replies=(await pool.query(`SELECT r.*,u.username FROM support_replies r JOIN users u ON u.id=r.sender_id WHERE ticket_id=ANY($1::bigint[]) ORDER BY r.id ASC`,[ids])).rows;
  res.json({tickets:r.rows,replies});
});
app.post(['/support','/api/support'],auth,async(req,res)=>{
  const category=textField(req.body?.category,50)||'Genel'; const subject=textField(req.body?.subject,120)||'Destek'; const message=textField(req.body?.message,2000);
  if(!message)return res.status(400).json({error:'Destek mesajı gerekli.'});
  const count=await pool.query(`SELECT COUNT(*)::int n FROM support_tickets WHERE user_id=$1 AND status='open'`,[req.user.id]);
  if(Number(count.rows[0].n)>=3)return res.status(400).json({error:'Açık destek talebi sınırı 3.'});
  const r=await pool.query(`INSERT INTO support_tickets(user_id,category,body) VALUES($1,$2,$3) RETURNING *`,[req.user.id,`${category}: ${subject}`,message]); res.status(201).json({ticket:r.rows[0]});
});
app.post(['/support/:id/reply','/api/support/:id/reply'],auth,async(req,res)=>{
  const id=finiteInt(req.params.id,1); const text=textField(req.body?.text,2000); if(id===null||!text)return res.status(400).json({error:'Geçersiz yanıt.'});
  const t=await pool.query(`SELECT * FROM support_tickets WHERE id=$1`,[id]); if(!t.rows[0])return res.status(404).json({error:'Talep bulunamadı.'});
  const isStaff=['owner','fakeOwner','admin'].includes(req.user.role); if(!isStaff&&Number(t.rows[0].user_id)!==Number(req.user.id))return res.status(403).json({error:'Bu talebe erişemezsin.'});
  const r=await pool.query(`INSERT INTO support_replies(ticket_id,sender_id,body) VALUES($1,$2,$3) RETURNING *`,[id,req.user.id,text]); await pool.query(`UPDATE support_tickets SET updated_at=NOW() WHERE id=$1`,[id]); res.json({reply:r.rows[0]});
});
app.post(['/support/:id/close','/api/support/:id/close'],auth,async(req,res)=>{const id=finiteInt(req.params.id,1);if(id===null)return res.status(400).json({error:'Geçersiz talep.'});const t=await pool.query(`SELECT user_id FROM support_tickets WHERE id=$1`,[id]);if(!t.rows[0])return res.status(404).json({error:'Talep bulunamadı.'});if(Number(t.rows[0].user_id)!==Number(req.user.id)&&!['owner','fakeOwner','admin'].includes(req.user.role))return res.status(403).json({error:'Yetkin yok.'});await pool.query(`UPDATE support_tickets SET status='closed',updated_at=NOW() WHERE id=$1`,[id]);res.json({ok:true});});
app.delete(['/support/:id','/api/support/:id'],auth,requireRole('owner'),async(req,res)=>{const id=finiteInt(req.params.id,1);if(id===null)return res.status(400).json({error:'Geçersiz talep.'});await pool.query(`DELETE FROM support_tickets WHERE id=$1`,[id]);res.json({ok:true});});

app.post(['/family/create','/api/family/create'],auth,async(req,res)=>{
  const name=textField(req.body?.name,30); const capacity=finiteInt(req.body?.capacity,4,5); const cost=capacity===5?25000000000000:2800000000000;
  if(!name||name.length<2||capacity===null)return res.status(400).json({error:'Aile adı veya kapasitesi geçersiz.'});
  const c=await pool.connect(); try{await c.query('BEGIN'); const u=(await c.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1 FOR UPDATE`,[req.user.id])).rows[0]; if(u.family_id||u.familyId)return rollbackError(c,res,400,'Zaten bir aileye bağlısın.'); if(Number(u.money)<cost)return rollbackError(c,res,400,'Yeterli paran yok.');
    const f=(await c.query(`INSERT INTO families(name,leader_id,capacity) VALUES($1,$2,$3) RETURNING *`,[name,u.id,capacity])).rows[0];
    await c.query(`UPDATE users SET money=money-$1,family_id=$2,updated_at=NOW() WHERE id=$3`,[cost,f.id,u.id]); await c.query(`INSERT INTO family_members(family_id,user_id,family_role) VALUES($1,$2,'leader')`,[f.id,u.id]); await c.query('COMMIT'); res.json({user:cleanUser(await getUserById(u.id)),publicState:await publicState()});
  }catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Aile kurulamadı.'});}finally{c.release()}
});
app.get(['/family/chat','/api/family/chat'],auth,async(req,res)=>{if(!req.user.family_id&&!req.user.familyId)return res.status(400).json({error:'Bir ailede değilsin.'});const fid=Number(req.user.family_id||req.user.familyId);const m=await pool.query(`SELECT m.id,m.body AS text,m.created_at AS time,u.username,u.nickname,u.pp_url AS pp FROM family_messages m JOIN users u ON u.id=m.sender_id WHERE m.family_id=$1 ORDER BY m.id DESC LIMIT 100`,[fid]);const f=await pool.query(`SELECT id,name,icon,leader_id AS leader,capacity,cash,protection,factories,leave_cost,total_income,last_income FROM families WHERE id=$1`,[fid]);res.json({family:f.rows[0]?{...f.rows[0],id:Number(f.rows[0].id),leader:Number(f.rows[0].leader),cash:Number(f.rows[0].cash),protection:Number(f.rows[0].protection),factories:f.rows[0].factories||[]}:null,messages:m.rows.reverse()});});
app.post(['/family/chat','/api/family/chat'],auth,async(req,res)=>{const text=textField(req.body?.text,300);if(!text)return res.status(400).json({error:'Mesaj gerekli.'});const fid=Number(req.user.family_id||req.user.familyId);if(!fid)return res.status(400).json({error:'Bir ailede değilsin.'});const member=await pool.query(`SELECT 1 FROM family_members WHERE family_id=$1 AND user_id=$2`,[fid,req.user.id]);if(!member.rows[0])return res.status(403).json({error:'Aile üyesi değilsin.'});await pool.query(`INSERT INTO family_messages(family_id,sender_id,body) VALUES($1,$2,$3)`,[fid,req.user.id,text]);res.json(await (async()=>{const r=await pool.query(`SELECT id,body AS text,created_at AS time FROM family_messages WHERE family_id=$1 ORDER BY id DESC LIMIT 100`,[fid]);return {messages:r.rows.reverse()};})());});
app.post(['/family/funds','/api/family/funds'],auth,async(req,res)=>{const action=String(req.body?.action||'');const amount=finiteInt(req.body?.amount,1,10**15);const fid=Number(req.user.family_id||req.user.familyId);if(!fid||!['deposit','withdraw'].includes(action)||amount===null)return res.status(400).json({error:'Geçersiz kasa işlemi.'});const c=await pool.connect();try{await c.query('BEGIN');const u=(await c.query(`SELECT money FROM users WHERE id=$1 FOR UPDATE`,[req.user.id])).rows[0];const f=(await c.query(`SELECT * FROM families WHERE id=$1 FOR UPDATE`,[fid])).rows[0];if(!f)return rollbackError(c,res,404,'Aile bulunamadı.');if(action==='deposit'){if(Number(u.money)<amount)return rollbackError(c,res,400,'Yeterli paran yok.');await c.query(`UPDATE users SET money=money-$1 WHERE id=$2`,[amount,req.user.id]);await c.query(`UPDATE families SET cash=cash+$1 WHERE id=$2`,[amount,fid]);}else{if(Number(f.cash)<amount)return rollbackError(c,res,400,'Aile kasasında yeterli para yok.');await c.query(`UPDATE families SET cash=cash-$1 WHERE id=$2`,[amount,fid]);await c.query(`UPDATE users SET money=money+$1 WHERE id=$2`,[amount,req.user.id]);}const nu=await getUserById(req.user.id,c);await c.query('COMMIT');res.json({user:cleanUser(nu),publicState:await publicState()});}catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Kasa işlemi başarısız.'});}finally{c.release()}});
app.post(['/family/protection','/api/family/protection'],auth,async(req,res)=>{const fid=Number(req.user.family_id||req.user.familyId);if(!fid)return res.status(400).json({error:'Bir ailede değilsin.'});const c=await pool.connect();try{await c.query('BEGIN');const f=(await c.query(`SELECT * FROM families WHERE id=$1 FOR UPDATE`,[fid])).rows[0];const u=(await c.query(`SELECT money FROM users WHERE id=$1 FOR UPDATE`,[req.user.id])).rows[0];if(!f)return rollbackError(c,res,404,'Aile bulunamadı.');if(Number(u.money)<1000000)return rollbackError(c,res,400,'Koruma için 1M gerekir.');await c.query(`UPDATE users SET money=money-1000000 WHERE id=$1`,[req.user.id]);await c.query(`UPDATE families SET protection=protection+1 WHERE id=$1`,[fid]);const nu=await getUserById(req.user.id,c);await c.query('COMMIT');res.json({user:cleanUser(nu),publicState:await publicState()});}catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Koruma alınamadı.'});}finally{c.release()}});
app.post(['/family/factory/buy','/api/family/factory/buy'],auth,async(req,res)=>{const fid=Number(req.user.family_id||req.user.familyId);const id=textField(req.body?.factoryId,50);const prices={horse:5000000,arms:25000000,casino:40000000,alcohol:50000000,tech:75000000,auto:100000000,textile:35000000,food:20000000};if(!fid||!id||prices[id]==null)return res.status(400).json({error:'Geçersiz fabrika.'});const c=await pool.connect();try{await c.query('BEGIN');const f=(await c.query(`SELECT * FROM families WHERE id=$1 FOR UPDATE`,[fid])).rows[0];const u=(await c.query(`SELECT money FROM users WHERE id=$1 FOR UPDATE`,[req.user.id])).rows[0];if(!f)return rollbackError(c,res,404,'Aile bulunamadı.');if(Number(f.leader_id)!==Number(req.user.id))return rollbackError(c,res,403,'Sadece aile lideri fabrika alabilir.');const fac=Array.isArray(f.factories)?f.factories:[];if(fac.includes(id))return rollbackError(c,res,400,'Bu fabrika zaten ailede.');if(Number(u.money)<prices[id])return rollbackError(c,res,400,'Yeterli paran yok.');await c.query(`UPDATE users SET money=money-$1 WHERE id=$2`,[prices[id],req.user.id]);fac.push(id);await c.query(`UPDATE families SET factories=$1 WHERE id=$2`,[JSON.stringify(fac),fid]);const nu=await getUserById(req.user.id,c);await c.query('COMMIT');res.json({user:cleanUser(nu),publicState:await publicState()});}catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Fabrika satın alınamadı.'});}finally{c.release()}});

app.post(['/trade/transaction','/api/trade/transaction'],auth,async(req,res)=>{const type=String(req.body?.type||'');const index=finiteInt(req.body?.index,0,6);const qty=finiteInt(req.body?.qty,1,1000000);if(!['weapon','tech'].includes(type)||index===null||qty===null)return res.status(400).json({error:'Geçersiz ticaret.'});const seed=Math.floor(Date.now()/150000);const rnd=n=>{let x=Math.sin(seed+n)*10000;return x-Math.floor(x)};const base=type==='weapon'?500000:800000;const price=Math.floor(base*(0.75+rnd(index)*0.5));const total=price*qty;const c=await pool.connect();try{await c.query('BEGIN');const u=(await c.query(`SELECT ${USER_PUBLIC} FROM users WHERE id=$1 FOR UPDATE`,[req.user.id])).rows[0];if(Number(u.money)<total)return rollbackError(c,res,400,'Yeterli paran yok.');await c.query(`UPDATE users SET money=money-$1,updated_at=NOW() WHERE id=$2`,[total,u.id]);await c.query(`INSERT INTO market_trades(user_id,trade_type,item_key,country,quantity,unit_price) VALUES($1,'buy',$2,$3,$4,$5)`,[u.id,`${type}:${index}`,u.country,qty,price]);await c.query(`INSERT INTO inventory_items(user_id,item_key,quantity) VALUES($1,$2,$3) ON CONFLICT(user_id,item_key) DO UPDATE SET quantity=inventory_items.quantity+EXCLUDED.quantity`,[u.id,`${type}:${index}`,qty]);const nu=await getUserById(u.id,c);await c.query('COMMIT');res.json({user:cleanUser(nu),price,total});}catch(e){try{await c.query('ROLLBACK')}catch(_){}console.error(e);res.status(500).json({error:'Ticaret başarısız.'});}finally{c.release()}});

app.get(['/travel/status','/api/travel/status'],auth,async(req,res)=>{const r=await pool.query(`SELECT id,destination_country,plane_id,started_at,arrives_at,status FROM travel_orders WHERE user_id=$1 ORDER BY id DESC LIMIT 1`,[req.user.id]);const o=r.rows[0];if(o&&o.status==='active'&&new Date(o.arrives_at)<=new Date()){await pool.query(`UPDATE users SET country=$1,airport_country=$1,updated_at=NOW() WHERE id=$2`,[o.destination_country,req.user.id]);await pool.query(`UPDATE travel_orders SET status='completed' WHERE id=$1`,[o.id]);o.status='completed';}res.json({travel:o||null,user:cleanUser(await getUserById(req.user.id))});});


app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'Beklenmeyen sunucu hatası.'});});

pool.query('SELECT 1').then(()=>ensureOnlineSchema()).then(()=>ensureCrimeDefinitions()).then(()=>bootstrapOwner()).then(()=>app.listen(PORT,()=>console.log(`KanHanedanı API listening on ${PORT}`))).catch(e=>{console.error('PostgreSQL başlangıç hatası:',e);process.exit(1);});
