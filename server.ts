import express from 'express';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { getDatabaseService, IDatabaseService } from './server/db';
import { getStorageService, IStorageService } from './server/storage';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const localUploadsDir = path.join(__dirname, 'data_store', 'uploads');
if (!fs.existsSync(localUploadsDir)) fs.mkdirSync(localUploadsDir, { recursive: true });
app.use('/uploads', express.static(localUploadsDir));

function hashPasswordWithSalt(password: string, salt?: string): { hash: string; salt: string } {
  const chosenSalt = salt || crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, chosenSalt, 64);
  return { hash: derivedKey.toString('hex'), salt: chosenSalt };
}

function verifyPassword(password: string, hash: string, salt: string): boolean {
  try {
    const derivedKey = crypto.scryptSync(password, salt, 64);
    const keyBuffer = Buffer.from(derivedKey.toString('hex'), 'hex');
    const hashBuffer = Buffer.from(hash, 'hex');
    return crypto.timingSafeEqual(keyBuffer, hashBuffer);
  } catch {
    return false;
  }
}

const loginAttempts: Record<string, { count: number; resetAt: number }> = {};
function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = loginAttempts[ip];
  if (!record || now > record.resetAt) {
    loginAttempts[ip] = { count: 1, resetAt: now + 60000 };
    return true;
  }
  if (record.count >= 20) {
    return false;
  }
  record.count += 1;
  return true;
}

let db: IDatabaseService;
let storage: IStorageService;

async function requireAdminAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Missing or invalid token' });
  }

  const token = authHeader.substring(7);
  try {
    const session = await db.getSession(token);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Unauthorized: Session invalid or expired' });
    }
    (req as any).adminSession = session;
    next();
  } catch (err) {
    console.error('Session verification error:', err);
    return res.status(500).json({ success: false, error: 'Internal auth service error' });
  }
}

app.post('/api/admin/login', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ success: false, error: 'Too many login attempts. Please wait 1 minute.' });
  }

  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password required' });
  }

  try {
    const cleanUser = String(username).trim();
    const cleanPass = String(password).trim();

    let adminUser = await db.getAdminUser(cleanUser);
    
    if (!adminUser && cleanUser.toLowerCase() === 'admin') {
      const initial = hashPasswordWithSalt('admin123');
      await db.saveAdminUser('admin', initial.hash, initial.salt);
      adminUser = await db.getAdminUser('admin');
      console.log('Notice: Initialized root administrator account.');
    }

    if (!adminUser) {
      return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }

    const isMatch = verifyPassword(cleanPass, adminUser.passwordHash, adminUser.salt);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid username or password' });
    }

    const token = 'sec_' + crypto.randomBytes(32).toString('hex');
    const session = {
      token,
      username: adminUser.username,
      loginTime: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    };

    await db.createSession(session);
    return res.json({ success: true, session });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, error: 'Database authentication unavailable' });
  }
});

app.post('/api/admin/change-password', requireAdminAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ success: false, error: 'Both current and new password required' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ success: false, error: 'New password must be at least 6 characters' });
  }

  try {
    const session = (req as any).adminSession;
    const adminUser = await db.getAdminUser(session.username);
    if (!adminUser) {
      return res.status(404).json({ success: false, error: 'Admin account not found' });
    }

    const isCurrentValid = verifyPassword(String(oldPassword), adminUser.passwordHash, adminUser.salt);
    if (!isCurrentValid) {
      return res.status(401).json({ success: false, error: 'Current password is incorrect' });
    }

    const newHashResult = hashPasswordWithSalt(String(newPassword));
    await db.saveAdminUser(adminUser.username, newHashResult.hash, newHashResult.salt);
    await db.invalidateAllSessions();

    const newToken = 'sec_' + crypto.randomBytes(32).toString('hex');
    const newSession = {
      username: adminUser.username,
      token: newToken,
      loginTime: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    };
    await db.createSession(newSession);

    return res.json({
      success: true,
      message: 'Password successfully updated across all devices',
      session: newSession
    });
  } catch (err) {
    console.error('Password change error:', err);
    return res.status(500).json({ success: false, error: 'Failed to persist new password' });
  }
});

app.post('/api/admin/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    await db.deleteSession(token);
  }
  return res.json({ success: true });
});

app.get('/api/admin/verify-session', requireAdminAuth, (req, res) => {
  return res.json({ success: true, session: (req as any).adminSession });
});

// PROTECTED: Only authenticated admin can view submitted requests (protecting privacy)
app.get('/api/requests', requireAdminAuth, async (req, res) => {
  try {
    const all = await db.listCustomerRequests();
    res.json({ success: true, data: all });
  } catch (err) {
    console.error('Error listing requests:', err);
    res.status(500).json({ success: false, error: 'Database query failed' });
  }
});

// PUBLIC: Any visitor from any device can submit sourcing requests
app.post('/api/requests', async (req, res) => {
  const { productName, description, referenceImages, contactType, contactHandle, targetBudget } = req.body;
  if (!productName || !contactHandle) {
    return res.status(400).json({ success: false, error: 'Missing productName or contactHandle' });
  }

  try {
    const processedImages: string[] = [];
    if (Array.isArray(referenceImages)) {
      for (let i = 0; i < Math.min(referenceImages.length, 3); i++) {
        const img = referenceImages[i];
        if (typeof img === 'string') {
          if (img.startsWith('data:image/')) {
            const matches = img.match(/^data:image\/([a-zA-Z0-9+]+);base64,(.+)$/);
            if (matches) {
              const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
              const buffer = Buffer.from(matches[2], 'base64');
              if (buffer.length <= 5 * 1024 * 1024) {
                const storedUrl = await storage.saveImage(buffer, ext);
                processedImages.push(storedUrl);
              }
            }
          } else if (img.startsWith('http') || img.startsWith('/uploads/')) {
            processedImages.push(img);
          }
        }
      }
    }

    const newReq = {
      id: 'req_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex'),
      productName: String(productName).trim().substring(0, 150),
      description: String(description || '').trim().substring(0, 1000),
      referenceImages: processedImages,
      contactType: contactType || 'discord',
      contactHandle: String(contactHandle).trim().substring(0, 100),
      targetBudget: String(targetBudget || '').trim().substring(0, 50),
      status: 'pending',
      createdAt: new Date().toISOString()
    };

    await db.createCustomerRequest(newReq);
    res.status(201).json({ success: true, data: newReq });
  } catch (err) {
    console.error('Error creating customer request:', err);
    res.status(500).json({ success: false, error: 'Database failed to store request' });
  }
});

app.put('/api/requests/:id', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  const { status, adminNotes } = req.body;
  try {
    const updated = await db.updateCustomerRequest(id, { status, adminNotes });
    if (!updated) {
      return res.status(404).json({ success: false, error: 'Request not found' });
    }
    res.json({ success: true, data: updated });
  } catch (err) {
    console.error('Error updating request:', err);
    res.status(500).json({ success: false, error: 'Database update failed' });
  }
});

app.delete('/api/requests/:id', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await db.getCustomerRequest(id);
    if (existing && Array.isArray(existing.referenceImages)) {
      for (const imgUrl of existing.referenceImages) {
        await storage.deleteImage(imgUrl);
      }
    }
    const deleted = await db.deleteCustomerRequest(id);
    if (!deleted) {
      return res.status(404).json({ success: false, error: 'Request not found' });
    }
    res.json({ success: true, message: 'Request deleted successfully' });
  } catch (err) {
    console.error('Error deleting request:', err);
    res.status(500).json({ success: false, error: 'Database delete failed' });
  }
});

app.get('/api/analytics', async (req, res) => {
  try {
    const data = await db.getAnalytics();
    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to read analytics' });
  }
});

app.post('/api/analytics/pageview', async (req, res) => {
  try {
    const { visitorId } = req.body;
    const store = await db.getAnalytics();
    const today = new Date().toISOString().split('T')[0];

    store.pageViews = (store.pageViews || 0) + 1;
    if (!store.daily) store.daily = {};
    if (!store.daily[today]) {
      store.daily[today] = {
        date: today,
        pageViews: 0,
        uniqueVisitors: 0,
        productClicks: 0,
        searches: 0,
        topAgents: {},
        visitors: {}
      };
    }
    store.daily[today].pageViews += 1;

    if (visitorId) {
      if (!store.daily[today].visitors) store.daily[today].visitors = {};
      if (!store.daily[today].visitors[visitorId]) {
        store.daily[today].visitors[visitorId] = true;
        store.daily[today].uniqueVisitors = Object.keys(store.daily[today].visitors).length;
      }
    }

    await db.saveAnalytics(store);
    res.json({ success: true, pageViews: store.pageViews });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to track pageview' });
  }
});

app.post('/api/analytics/clear', requireAdminAuth, async (req, res) => {
  try {
    await db.saveAnalytics({
      pageViews: 0,
      daily: {},
      products: {},
      agents: {},
      visitors: {}
    });
    res.json({ success: true, message: 'All analytics cleared' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to clear analytics' });
  }
});

async function startServer() {
  db = await getDatabaseService();
  storage = getStorageService();

  if (process.env.NODE_ENV === 'production' || fs.existsSync(path.join(__dirname, 'dist'))) {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✓ BESTR3PS Server running on port ${PORT} [Mode: ${process.env.NODE_ENV || 'development'}]`);
    console.log(`✓ Storage Provider: ${storage.constructor.name}`);
    console.log(`✓ Database Provider: ${db.constructor.name}`);
  });
}

// Initialize db and storage
getDatabaseService().then(d => { db = d; });
storage = getStorageService();

// Standalone environment execution
if (!process.env.VERCEL) {
  startServer();
}

// Export default app for Vercel Serverless Function entrypoint
export default app;
