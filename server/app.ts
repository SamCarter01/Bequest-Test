import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import jwt, { JwtPayload } from 'jsonwebtoken';
import helmet from 'helmet';
import cors, { CorsOptions } from 'cors';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import * as dotenv from 'dotenv';
import https from 'https';
import fs from 'fs';

dotenv.config();

const PORT = 8080;
const app = express();

app.use(bodyParser.json());
app.use(helmet());
app.use(morgan('combined'));

const whitelist: string[] = [
  'http://localhost:3000'
];

const corsOptions: CorsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));

// Simulated database
let userData = {
  username: 'SamCarter',
  data: '', // Empty for now, will be populated after encryption
};

// Environment variables
const jwtSecretKey = process.env.JWT_SECRET as string;
const encryptionKey = process.env.CRYPTO_KEY as string;

// Read private key from .env
const privateKey = fs.readFileSync(process.env.PRIVATE_KEY!, 'utf8');
const certificate = fs.readFileSync(process.env.CERTIFICATE!, 'utf8');
const credentials = { key: privateKey, cert: certificate };

// Interface extension to include 'decoded' property in Request
interface DecodedRequest extends Request {
  decoded?: JwtPayload | string;
}

// Middleware to verify JWT
const verifyJWT = (req: DecodedRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized - Missing token' });
  }

  jwt.verify(token, jwtSecretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token' });
    }

    req.decoded = decoded;
    next();
  });
};

// Middleware to encrypt and decrypt sensitive data
const encryptData = (data: string, key: string): string => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encryptedData = cipher.update(data, 'utf-8', 'hex');
  encryptedData += cipher.final('hex');
  return iv.toString('hex') + encryptedData;
};

const decryptData = (encryptedData: string, key: string): string => {
  const iv = Buffer.from(encryptedData.slice(0, 32), 'hex'); // Extract IV from the encrypted data
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let decryptedData = decipher.update(encryptedData.slice(32), 'hex', 'utf-8');
  decryptedData += decipher.final('utf-8');
  return decryptedData;
};

// Get user data
app.get('/', verifyJWT, (req: DecodedRequest, res: Response) => {
  // Decrypt sensitive data before sending it to the client
  const decryptedData = userData.data !== '' ? decryptData(userData.data, encryptionKey) : '';
  res.json({ username: userData.username, data: decryptedData });
});

// Update user data
app.post('/', verifyJWT, (req: DecodedRequest, res: Response) => {
  // Ensure that req.decoded is of type JwtPayload
  const decoded = req.decoded as JwtPayload;

  // Encrypt sensitive data before storing it
  const encryptedData = encryptData(req.body.data, encryptionKey);

  userData = { username: decoded.username as string, data: encryptedData };

  // Backup the data
  saveBackup(userData);
  res.json({ message: 'User data updated successfully' });
});

// Function to save backup data (customize this based on your storage requirements)
const saveBackup = (backupData: any) => {
  try {
    const backupFilePath = 'data_backup.json';
    fs.writeFileSync(backupFilePath, JSON.stringify(backupData));
    console.log(`Backup successful: Data saved to ${backupFilePath}`);
  } catch (error) {
    console.error(`Backup failed: ${error}`);
  }
};

// Endpoint to restore backup
app.post('/restore', (req: Request, res: Response) => {
  try {
    const backupFilePath = 'data_backup.json';

    // Read backup data from the file
    const backupData = JSON.parse(fs.readFileSync(backupFilePath, 'utf-8'));

    // Update user data with the restored data
    userData = { username: backupData.username, data: backupData };
    
    res.json({ message: 'Backup restored successfully' });
  } catch (error) {
    console.error(`Restore failed: ${error}`);
    res.status(500).json({ error: 'Failed to restore backup' });
  }
});

// Generate JWT for authentication
app.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Validate username and password (replace with your authentication logic)
  if (username === 'SamCarter' && password === 'SamCarter') {
    const token = jwt.sign({ username }, jwtSecretKey, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});

app.use(limiter);

// Create an HTTPS server
const httpsServer = https.createServer(credentials, app);

httpsServer.listen(PORT, () => {
  console.log(`Server running on https://localhost:${PORT}`);
});
