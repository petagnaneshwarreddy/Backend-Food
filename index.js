require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const recipeRoutes = require("./routes/recipes");

const app = express();
const port = process.env.PORT || 5000;

/* ===========================
   STARTUP ENV CHECK
=========================== */
const requiredEnvVars = ["MONGODB_URI", "JWT_SECRET"];
const missingVars = requiredEnvVars.filter((v) => !process.env[v]);

if (missingVars.length > 0) {
  console.error(`❌ Missing ENV: ${missingVars.join(", ")}`);
  process.exit(1);
}

/* ===========================
   SECURITY MIDDLEWARE
=========================== */

app.use(helmet());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
}));

/* ===========================
   CORS (FIXED)
=========================== */

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);

    const allowed = [
      process.env.FRONTEND_URL,
      "http://localhost:3000"
    ];

    if (allowed.includes(origin)) {
      callback(null, true);
    } else {
      console.log("❌ Blocked:", origin);
      callback(new Error("CORS blocked"));
    }
  },
  credentials: true,
}));

app.options("*", cors());

/* ===========================
   GENERAL MIDDLEWARE
=========================== */

app.use(express.json());

app.use((req, res, next) => {
  console.log(`➡️ ${req.method} ${req.url}`);
  next();
});

app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/api/recipes", recipeRoutes);

app.get("/", (req, res) => {
  res.send("🚀 API Running");
});

/* ===========================
   DATABASE CONNECTION (FIXED)
=========================== */

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Connected"))
.catch((err) => {
  console.error("❌ DB Error:", err.message);
  process.exit(1);
});

/* ===========================
   JWT
=========================== */

const JWT_SECRET = process.env.JWT_SECRET;

const verifyToken = (req, res, next) => {
  const header = req.headers.authorization;

  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized - No token" });
  }

  const token = header.split(" ")[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });

    req.userId = decoded.userId;
    next();
  });
};

/* ===========================
   MODELS
=========================== */

const User = mongoose.model("User", new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, unique: true },
  password: String,
  resetToken: String,
}));

const WasteData = mongoose.model("WasteData", new mongoose.Schema({
  user: mongoose.Schema.Types.ObjectId,
  foodItem: String,
  foodQuantity: Number,
  foodReason: String,
  foodWasteDate: { type: Date, default: Date.now },
  location: String,
  image: String,
  approved: { type: Boolean, default: false },
}));

const Inventory = mongoose.model("Inventory", new mongoose.Schema({
  user: mongoose.Schema.Types.ObjectId,
  itemName: String,
  itemQuantity: Number,
  itemCost: Number,
  itemPurchaseDate: Date,
  itemExpiryDate: Date,
  consumed: { type: Boolean, default: false },
}));

/* ===========================
   MULTER (SECURE)
=========================== */

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = "./uploads";
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

/* ===========================
   EMAIL
=========================== */

const sendPasswordResetEmail = async (email, token) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const url = `${process.env.FRONTEND_URL}/reset-password/${token}`;

  await transporter.sendMail({
    from: process.env.EMAIL,
    to: email,
    subject: "Reset Password",
    html: `<a href="${url}">Reset Password</a>`,
  });
};

/* ===========================
   AUTH ROUTES
=========================== */

app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    if (password.length < 6)
      return res.status(400).json({ error: "Password too short" });

    if (await User.findOne({ email }))
      return res.status(409).json({ error: "Email exists" });

    const hash = await bcrypt.hash(password, 10);

    await new User({ username, email, password: hash }).save();

    res.status(201).json({ message: "Registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Register failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

/* ===========================
   PASSWORD RESET
=========================== */

app.post("/api/forgot-password", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    user.resetToken = token;
    await user.save();

    await sendPasswordResetEmail(user.email, token);

    res.json({ message: "Email sent" });
  } catch {
    res.status(500).json({ error: "Email failed" });
  }
});

app.post("/api/reset-password/:token", async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.resetToken !== req.params.token)
      return res.status(400).json({ error: "Invalid/expired token" });

    user.password = await bcrypt.hash(req.body.password, 10);
    user.resetToken = null;

    await user.save();

    res.json({ message: "Password reset success" });
  } catch {
    res.status(500).json({ error: "Reset failed" });
  }
});

/* ===========================
   WASTE ROUTES
=========================== */

app.post("/api/waste", verifyToken, upload.single("image"), async (req, res) => {
  const waste = new WasteData({
    ...req.body,
    user: req.userId,
    image: req.file?.filename || null,
  });

  await waste.save();
  res.json(waste);
});

app.get("/api/waste", verifyToken, async (req, res) => {
  res.json(await WasteData.find({ user: req.userId }));
});

/* ===========================
   INVENTORY ROUTES
=========================== */

app.post("/api/inventory", verifyToken, async (req, res) => {
  const item = new Inventory({ ...req.body, user: req.userId });
  await item.save();
  res.json(item);
});

app.get("/api/inventory", verifyToken, async (req, res) => {
  res.json(await Inventory.find({ user: req.userId }));
});

/* ===========================
   GLOBAL ERROR HANDLER
=========================== */

app.use((err, req, res, next) => {
  console.error("❌ Error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

/* ===========================
   START SERVER
=========================== */

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});