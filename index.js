// =================================================================
// Backend Complet pour CASBAH-LUXE AUTOMOBILE
// =================================================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
require('dotenv').config();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connexion à MongoDB réussie.'))
  .catch(err => console.error('Erreur de connexion à MongoDB:', err));

const UserSchema = new mongoose.Schema({
  nom: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
}, { timestamps: true });

const CandidatureSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  telephone: { type: String, required: true },
  poste: { type: String, required: true },
  motivation: { type: String, required: true },
  cvPath: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Candidature = mongoose.model('Candidature', CandidatureSchema);

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Accès non autorisé, token manquant.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token invalide.' });
  }
};

const apiRouter = express.Router();
app.use('/api', apiRouter);

apiRouter.post('/auth/register', async (req, res) => {
  const { nom, email, password } = req.body;
  if (!nom || !email || !password) {
      return res.status(400).json({ message: "Veuillez fournir nom, email et mot de passe."});
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Cet email est déjà utilisé.' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({ nom, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'Utilisateur créé avec succès.' });
  } catch (error) {
    res.status(500).json({ message: 'Erreur du serveur.', error: error.message });
  }
});

apiRouter.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Email ou mot de passe incorrect.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Email ou mot de passe incorrect.' });
    }
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({ message: 'Connexion réussie', token });
  } catch (error) {
    res.status(500).json({ message: 'Erreur du serveur.', error: error.message });
  }
});

apiRouter.post('/candidatures', authMiddleware, upload.single('cv'), async (req, res) => {
  const { telephone, poste, motivation } = req.body;
  if (!req.file) {
      return res.status(400).json({ message: "Le fichier CV est manquant."});
  }
  try {
    const candidature = new Candidature({
      userId: req.user.userId,
      telephone,
      poste,
      motivation,
      cvPath: req.file.path,
    });
    await candidature.save();
    res.status(201).json({ message: 'Candidature envoyée avec succès.' });
  } catch (error) {
    res.status(500).json({ message: 'Erreur du serveur.', error: error.message });
  }
});

apiRouter.get('/candidatures', authMiddleware, async (req, res) => {
    try {
        const candidatures = await Candidature.find().populate('userId', 'nom email');
        res.json(candidatures);
    } catch (error) {
        res.status(500).json({ message: 'Erreur du serveur.', error: error.message });
    }
});

app.listen(PORT, () => {
  console.log(`Le serveur est lancé sur le port ${PORT}`);
});
