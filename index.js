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
   CORS — MUST BE FIRST
   Before helmet & rate limiter
   so OPTIONS preflight always works
=========================== */
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const allowed = [
      process.env.FRONTEND_URL,
      "http://localhost:3000",
    ];
    if (allowed.includes(origin)) {
      callback(null, true);
    } else {
      console.log("❌ CORS Blocked:", origin);
      callback(new Error("CORS blocked"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

// Preflight FIRST before any other middleware
app.options("*", cors(corsOptions));
app.use(cors(corsOptions));

/* ===========================
   SECURITY MIDDLEWARE
=========================== */
app.use(helmet());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: (req) => req.method === "OPTIONS",
  standardHeaders: true,
  legacyHeaders: false,
}));

/* ===========================
   GENERAL MIDDLEWARE
=========================== */
app.use(express.json());

app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.url}`);
  next();
});

// Serve uploaded images — both paths supported
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/api/uploads", express.static(path.join(__dirname, "uploads")));

app.use("/api/recipes", recipeRoutes);

app.get("/", (req, res) => res.send("🚀 API Running"));

/* ===========================
   DATABASE CONNECTION
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
  if (!header?.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized - No token" });

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
  username:   { type: String, required: true },
  email:      { type: String, unique: true },
  phone:      { type: String, default: "" },
  password:   String,
  resetToken: String,
}));

const WasteData = mongoose.model("WasteData", new mongoose.Schema({
  user:          mongoose.Schema.Types.ObjectId,
  foodItem:      String,
  foodQuantity:  Number,
  foodReason:    String,
  foodWasteDate: { type: Date, default: Date.now },
  location:      String,
  image:         String,
  approved:      { type: Boolean, default: false },
}));

const Inventory = mongoose.model("Inventory", new mongoose.Schema({
  user:             mongoose.Schema.Types.ObjectId,
  itemName:         String,
  itemQuantity:     Number,
  itemCost:         Number,
  itemPurchaseDate: Date,
  itemExpiryDate:   Date,
  consumed:         { type: Boolean, default: false },
}));

/* ===========================
   MULTER
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
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const url = `${process.env.FRONTEND_URL}/reset-password/${token}`;
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
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
    const { username, email, password, phone } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    if (password.length < 6)
      return res.status(400).json({ error: "Password too short (min 6 chars)" });

    if (await User.findOne({ email }))
      return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    await new User({ username, email, password: hash, phone: phone || "" }).save();

    res.status(201).json({ message: "Registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
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

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
    user.resetToken = token;
    await user.save();

    await sendPasswordResetEmail(user.email, token);
    res.json({ message: "Reset email sent" });
  } catch {
    res.status(500).json({ error: "Email failed" });
  }
});

app.post("/api/reset-password/:token", async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.resetToken !== req.params.token)
      return res.status(400).json({ error: "Invalid or expired token" });

    user.password = await bcrypt.hash(req.body.password, 10);
    user.resetToken = null;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch {
    res.status(500).json({ error: "Reset failed" });
  }
});

/* ===========================
   WASTE ROUTES
=========================== */

// Create waste entry
app.post("/api/waste", verifyToken, upload.single("image"), async (req, res) => {
  try {
    const waste = new WasteData({
      ...req.body,
      user: req.userId,
      image: req.file?.filename || null,
    });
    await waste.save();
    res.status(201).json(waste);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save waste entry" });
  }
});

// Get all waste entries for logged-in user
app.get("/api/waste", verifyToken, async (req, res) => {
  try {
    const data = await WasteData.find({ user: req.userId }).sort({ foodWasteDate: -1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch waste data" });
  }
});

// Delete waste entry
app.delete("/api/waste/:id", verifyToken, async (req, res) => {
  try {
    const waste = await WasteData.findOne({ _id: req.params.id, user: req.userId });
    if (!waste)
      return res.status(404).json({ error: "Entry not found or not authorised" });

    // Delete image file from disk if it exists
    if (waste.image) {
      const imgPath = path.join(__dirname, "uploads", waste.image);
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }

    await waste.deleteOne();
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete entry" });
  }
});

// Approve waste entry (mark sold out, reduce quantity by 10%)
app.patch("/api/waste/approve/:id", verifyToken, async (req, res) => {
  try {
    const waste = await WasteData.findOne({ _id: req.params.id, user: req.userId });
    if (!waste)
      return res.status(404).json({ error: "Entry not found or not authorised" });

    waste.approved = true;
    if (req.body.foodQuantity !== undefined) waste.foodQuantity = req.body.foodQuantity;
    await waste.save();

    res.json({ message: "Approved successfully", data: waste });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to approve entry" });
  }
});

/* ===========================
   INVENTORY ROUTES
=========================== */
app.post("/api/inventory", verifyToken, async (req, res) => {
  try {
    const item = new Inventory({ ...req.body, user: req.userId });
    await item.save();
    res.status(201).json(item);
  } catch (err) {
    res.status(500).json({ error: "Failed to save inventory item" });
  }
});

app.get("/api/inventory", verifyToken, async (req, res) => {
  try {
    res.json(await Inventory.find({ user: req.userId }));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch inventory" });
  }
});

/* ===========================
   GLOBAL ERROR HANDLER
=========================== */
app.use((err, req, res, next) => {
  console.error("❌ Error:", err.message);
  if (err.message === "CORS blocked")
    return res.status(403).json({ error: "CORS blocked" });
  res.status(500).json({ error: "Internal server error" });
});

/* ===========================
   START SERVER
=========================== */
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});