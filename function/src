const { onRequest } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors')({ origin: true });

admin.initializeApp();
const db = admin.firestore();
const storage = admin.storage().bucket();
const FieldValue = admin.firestore.FieldValue;
const TELEGRAM_BOT_TOKEN = defineSecret('TELEGRAM_BOT_TOKEN');

const DEFAULT_PRODUCTS = [
  { id: 'p1', name: 'NordVPN Premium', category: 'vpn', price: 30, stock: true, plans: [{ name: '1 Month', price: 30 }, { name: '6 Months', price: 150 }] },
  { id: 'p2', name: 'Residential Proxy', category: 'proxy', price: 150, stock: true, plans: [] },
  { id: 'p3', name: 'Outlook / Hotmail Mail', category: 'mail', price: 1, stock: true, plans: [] },
  { id: 'p4', name: 'Telegram Premium', category: 'app', price: 250, stock: true, plans: [] },
  { id: 'p5', name: 'USA Virtual Number', category: 'number', price: 8, stock: true, plans: [] }
];

function json(res, code, body) { return res.status(code).json(body); }
function now() { return FieldValue.serverTimestamp(); }
function uidFromAuth(req) { return req.user?.uid || null; }

async function authenticate(req, res) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) { json(res, 401, { success:false, error:'Unauthorized: Token missing' }); return null; }
  try {
    const decoded = await admin.auth().verifyIdToken(h.slice(7), true);
    req.user = decoded;
    return decoded;
  } catch (e) {
    json(res, 401, { success:false, error:'Unauthorized: Invalid Firebase ID token' });
    return null;
  }
}

async function isAdmin(uid) {
  if (!uid) return false;
  const snap = await db.doc(`admin_users/${uid}`).get();
  return snap.exists && snap.data().status === 'active';
}

async function audit(uid, action, details = {}) {
  await db.collection('audit_logs').add({ uid, action, details, createdAt: now() });
}

function validateTelegramInitData(initData, botToken) {
  const params = new URLSearchParams(initData || '');
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const dataCheckString = [...params.entries()].sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => `${k}=${v}`).join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const calculated = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(calculated), Buffer.from(hash))) return null;
  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || (Date.now()/1000 - authDate) > 86400) return null;
  let user = {};
  try { user = JSON.parse(params.get('user') || '{}'); } catch { return null; }
  if (!user.id) return null;
  return user;
}

async function ensureUser(tg) {
  const telegramId = String(tg.id);
  const ref = db.doc(`users/${telegramId}`);
  const snap = await ref.get();
  const base = {
    tgId: telegramId,
    telegramId,
    firstName: tg.first_name || 'User',
    lastName: tg.last_name || '',
    username: tg.username || '',
    photoUrl: tg.photo_url || '',
    languageCode: tg.language_code || '',
    updatedAt: now(),
    lastLoginAt: now()
  };
  if (!snap.exists) {
    await ref.set({ ...base, balance: 0, referralBalance: 0, totalEarned: 0, referredBy: null, joinedAt: now(), status: 'active' });
  } else await ref.set(base, { merge: true });
  const userRecord = await admin.auth().getUserByEmail(`tg_${telegramId}@ayno.local`).catch(async () => {
    try { return await admin.auth().createUser({ uid: `tg_${telegramId}`, displayName: `${tg.first_name || ''} ${tg.last_name || ''}`.trim() }); } catch { return null; }
  });
  const firebaseUid = userRecord?.uid || `tg_${telegramId}`;
  return { ref, firebaseUid, user: { ...(snap.exists ? snap.data() : {}), ...base, tgId: telegramId, telegramId } };
}

async function getUserByAuth(uid) {
  const q = await db.collection('users').where('firebaseUid', '==', uid).limit(1).get();
  if (!q.empty) return q.docs[0];
  if (uid.startsWith('tg_')) {
    const ref = db.doc(`users/${uid.slice(3)}`); const snap = await ref.get(); if (snap.exists) return snap;
  }
  return null;
}

async function route(req, res) {
  const path = req.path.replace(/\/$/, '') || '/';
  if (path === '/api/health' || path === '/health') return json(res, 200, { status:'healthy', server:'firebase-functions', database:'firestore', timestamp:new Date().toISOString() });

  if (path === '/api/auth/telegram' && req.method === 'POST') {
    const tg = validateTelegramInitData(req.body?.initData, TELEGRAM_BOT_TOKEN.value());
    if (!tg) return json(res, 401, { success:false, error:'Invalid or expired Telegram initData' });
    const { ref, firebaseUid, user } = await ensureUser(tg);
    await ref.set({ firebaseUid }, { merge:true });
    const customToken = await admin.auth().createCustomToken(firebaseUid, { telegramId:String(tg.id) });
    return json(res, 200, { success:true, customToken, token:customToken, user:{...user, firebaseUid} });
  }

  const publicData = path === '/api/data' || path === '/api/app-data' || (path === '/api/reviews' && req.method === 'GET');
  let uid = null, userDoc = null, userData = null;
  if (!publicData) {
    uid = await authenticate(req, res);
    if (!uid) return;
    userDoc = await getUserByAuth(uid.uid);
    userData = userDoc?.data() || null;
  }

  if (path === '/api/data' || path === '/api/app-data') {
    const productsSnap = await db.collection('products').get();
    if (productsSnap.empty) {
      const batch = db.batch(); DEFAULT_PRODUCTS.forEach(p => batch.set(db.doc(`products/${p.id}`), {...p, createdAt:now(), updatedAt:now()})); await batch.commit();
    }
    const ps = await db.collection('products').get();
    const settingsSnap = await db.doc('settings/app').get();
    const settings = settingsSnap.exists ? settingsSnap.data() : { maintenance:false, minWithdraw:Number(process.env.MIN_WITHDRAW || 50) };
    return json(res,200,{success:true,products:ps.docs.map(d=>({id:d.id,...d.data()})),settings,user:userData});
  }

  if (path === '/api/user' && req.method === 'GET') return json(res,200,{success:true,user:userData});

  if (path === '/api/orders' && req.method === 'GET') {
    const q = await db.collection('orders').where('userId','==',userData?.firebaseUid || uid.uid).orderBy('createdAt','desc').get().catch(async()=>db.collection('orders').where('userId','==',userData?.firebaseUid || uid.uid).get());
    return json(res,200,{success:true,orders:q.docs.map(d=>({id:d.id,...d.data()}))});
  }

  if (path === '/api/orders' && req.method === 'POST') {
    const {item,price,method,trxId,id,tgId,status} = req.body || {};
    if (!item || price === undefined || !method || !trxId) return json(res,400,{success:false,error:'Missing required fields'});
    const numericPrice=Number(price); if (!Number.isFinite(numericPrice) || numericPrice < 0) return json(res,400,{success:false,error:'Invalid price'});
    const orderId=id || ('AYN'+crypto.randomInt(100000,999999));
    const ref=db.doc(`orders/${orderId}`);
    await ref.create({userId:userData?.firebaseUid || uid.uid,tgId:tgId || userData?.tgId || null,item,price:numericPrice,method,trxId,status:status || 'Pending',createdAt:now(),updatedAt:now()});
    return json(res,201,{success:true,order:{id:orderId,userId:userData?.firebaseUid || uid.uid,item,price:numericPrice,method,trxId,status:status || 'Pending'}});
  }

  if (path === '/api/withdraw' && req.method === 'POST') {
    const {method,account,amount} = req.body || {}; const n=Number(amount);
    if (!method || !account || !Number.isFinite(n) || n<=0) return json(res,400,{success:false,error:'Invalid withdrawal request'});
    const walletRef=db.doc(`wallets/${uid.uid}`); const withdrawalRef=db.collection('withdrawals').doc();
    await db.runTransaction(async tx=>{
      const w=(await tx.get(walletRef)).data() || {balance:0};
      if (Number(w.balance||0) < n) throw new Error('INSUFFICIENT_BALANCE');
      tx.set(walletRef,{balance:Number(w.balance)-n,updatedAt:now()},{merge:true});
      tx.set(withdrawalRef,{userId:uid.uid,method,account,amount:n,fee:0,netAmount:n,status:'pending',createdAt:now(),updatedAt:now()});
      tx.create(db.collection('wallet_ledger').doc(),{userId:uid.uid,type:'withdrawal',amount:-n,referenceId:withdrawalRef.id,createdAt:now()});
    }).catch(e=>{throw e;});
    return json(res,201,{success:true,withdrawalId:withdrawalRef.id,status:'pending'});
  }

  if (path === '/api/transfer' && req.method === 'POST') {
    const {receiverId,amount} = req.body || {}; const n=Number(amount);
    if (!receiverId || !Number.isFinite(n) || n<=0) return json(res,400,{success:false,error:'Invalid transfer'});
    if (receiverId===uid.uid) return json(res,400,{success:false,error:'Self transfer is not allowed'});
    const sref=db.doc(`wallets/${uid.uid}`), rref=db.doc(`wallets/${receiverId}`), tref=db.collection('transfers').doc();
    try { await db.runTransaction(async tx=>{ const s=(await tx.get(sref)).data()||{balance:0}; const r=(await tx.get(rref)).data()||{balance:0}; if(Number(s.balance||0)<n) throw new Error('INSUFFICIENT_BALANCE'); tx.set(sref,{balance:Number(s.balance)-n,updatedAt:now()},{merge:true}); tx.set(rref,{balance:Number(r.balance)+n,updatedAt:now()},{merge:true}); tx.create(tref,{senderId:uid.uid,receiverId,amount:n,status:'completed',createdAt:now()}); tx.create(db.collection('wallet_ledger').doc(),{userId:uid.uid,type:'transfer_debit',amount:-n,referenceId:tref.id,createdAt:now()}); tx.create(db.collection('wallet_ledger').doc(),{userId:receiverId,type:'transfer_credit',amount:n,referenceId:tref.id,createdAt:now()}); }); } catch(e){ return json(res,400,{success:false,error:e.message==='INSUFFICIENT_BALANCE'?'Insufficient balance':'Transfer failed'}); }
    return json(res,200,{success:true,transferId:tref.id});
  }

  if (path === '/api/users/search' && req.method === 'GET') {
    const q=String(req.query.q||'').trim().toLowerCase(); if(!q) return json(res,200,{success:true,users:[]});
    const snap=await db.collection('users').limit(50).get(); const users=snap.docs.map(d=>({id:d.id,...d.data()})).filter(u=>(u.username||'').toLowerCase().includes(q)||(u.firstName||'').toLowerCase().includes(q)).slice(0,20);
    return json(res,200,{success:true,users});
  }

  if (path === '/api/reviews' && req.method === 'POST') {
    const body=req.body||{}; if(!body.productId || !body.rating) return json(res,400,{success:false,error:'Product and rating are required'});
    const ref=await db.collection('reviews').add({productId:body.productId,userId:uid.uid,rating:Number(body.rating),comment:String(body.comment||''),createdAt:now(),updatedAt:now()});
    return json(res,201,{success:true,id:ref.id});
  }
  if (path === '/api/reviews' && req.method === 'GET') {
    const productId=String(req.query.productId||''); let q=db.collection('reviews'); if(productId) q=q.where('productId','==',productId); const snap=await q.limit(100).get(); return json(res,200,{success:true,reviews:snap.docs.map(d=>({id:d.id,...d.data()}))});
  }

  if (path === '/api/user/notifications/ack' && req.method === 'POST') { const id=req.body?.id; if(!id) return json(res,400,{success:false,error:'Notification id required'}); await db.doc(`notifications/${id}`).set({read:true,readAt:now()},{merge:true}); return json(res,200,{success:true}); }

  if (path === '/api/logs/error' && req.method === 'POST') { await db.collection('audit_logs').add({uid:uid.uid,action:'client_error',details:req.body||{},createdAt:now()}); return json(res,200,{success:true,message:'Error logged'}); }

  if (path === '/api/verify-screenshot' && req.method === 'POST') {
    return json(res,400,{success:false,error:'Use Firebase Storage direct upload for screenshots; the legacy multipart endpoint has been removed with the Railway filesystem.'});
  }

  // External-provider operations are intentionally blocked until real provider secrets are configured.
  const providerPaths=['/api/smsbower/services','/api/smsbower/top-countries','/api/buy-external','/api/get-otp','/api/complete-order','/api/cancel-order','/api/mail/inbox','/api/ai-support','/api/tools/proxy-checker'];
  if(providerPaths.some(p=>path===p || path.startsWith(p+'/'))) return json(res,503,{success:false,error:'Provider integration requires production provider credentials and endpoint configuration. No mock response is returned.'});

  return json(res,404,{success:false,error:'API endpoint not found',path});
}

exports.api = onRequest({ region:'us-central1', cors:false, secrets:[TELEGRAM_BOT_TOKEN], timeoutSeconds:60, memory:'256MiB' }, (req,res)=>cors(req,res,()=>route(req,res).catch(e=>{ logger.error(e); return json(res,500,{success:false,error:'Internal server error'}); })));
