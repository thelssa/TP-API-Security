import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import https from 'https';
import fs from 'fs';

import config from './config.mjs';
import authRoutes from './controllers/route.mjs';
import authenticateToken from './controllers/auth.mjs';

const env = process.env.NODE_ENV || 'development';
const { port, mongodb } = config[env];

const app = express();

app.use(helmet());
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(rateLimit({ windowMs: 60 * 60 * 1000, max: 100 }));

mongoose.connect(mongodb, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('MongoDB connecté');
  const key = fs.readFileSync('server.key');
  const cert = fs.readFileSync('server.cert');
  https.createServer({ key, cert }, app).listen(port, () => {
    console.log(`Serveur HTTPS sur https://localhost:${port}`);
  });
}).catch((err) => console.error('Erreur MongoDB :', err));

app.use('/api/auth', authRoutes);

app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: `Accès sécurisé à ${req.user.email}` });
});

app.use((err, req, res) => {
  console.error(err);
  return res.status(500).json({ error: 'Erreur serveur' });
});
