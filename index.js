require("dotenv").config();
const express    = require("express");
const mongoose   = require("mongoose");
const cors       = require("cors");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer     = require("multer");
const path       = require("path");
const fs         = require("fs");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");

const recipeRoutes = require("./routes/recipes");

const app  = express();
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

const JWT_SECRET = process.env.JWT_SECRET;

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

// Handle ALL preflight requests before any other middleware
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

// Serve uploaded images — support both URL patterns
app.use("/uploads",     express.static(path.join(__dirname, "uploads")));
app.use("/api/uploads", express.static(path.join(__dirname, "uploads")));

app.use("/api/recipes", recipeRoutes);

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
   MULTER — File Uploads
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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
});

/* ===========================
   JWT MIDDLEWARE
=========================== */
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
    subject: "Reset Your FeedForward Password",
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;">
        <h2 style="color:#f97316;">Reset Your Password</h2>
        <p>Click the button below to reset your password. This link expires in 1 hour.</p>
        <a href="${url}" style="display:inline-block;margin-top:16px;padding:12px 28px;
          background:#f97316;color:#fff;border-radius:8px;text-decoration:none;font-weight:700;">
          Reset Password
        </a>
        <p style="margin-top:24px;color:#999;font-size:12px;">
          If you didn't request this, ignore this email.
        </p>
      </div>
    `,
  });
};

/* ===========================
   HEALTH & UTILITY ROUTES
=========================== */
app.get("/", (req, res) => res.send("🚀 FeedForward API Running"));

// Ping — frontend calls this on load to wake up Render free tier
app.get("/api/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

// Refresh token — returns a fresh 7-day token if current token is still valid
app.get("/api/refresh-token", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("_id email username");
    if (!user) return res.status(404).json({ error: "User not found" });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch {
    res.status(500).json({ error: "Could not refresh token" });
  }
});

/* ===========================
   AUTH ROUTES
=========================== */

// Register
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

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

/* ===========================
   PASSWORD RESET
=========================== */

// Request reset email
app.post("/api/forgot-password", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
    user.resetToken = token;
    await user.save();

    await sendPasswordResetEmail(user.email, token);
    res.json({ message: "Reset email sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Email failed" });
  }
});

// Confirm reset with new password
app.post("/api/reset-password/:token", async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.resetToken !== req.params.token)
      return res.status(400).json({ error: "Invalid or expired token" });

    if (!req.body.password || req.body.password.length < 6)
      return res.status(400).json({ error: "Password too short (min 6 chars)" });

    user.password = await bcrypt.hash(req.body.password, 10);
    user.resetToken = null;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error(err);
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
      user:  req.userId,
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

// Delete waste entry (also removes image file from disk)
app.delete("/api/waste/:id", verifyToken, async (req, res) => {
  try {
    const waste = await WasteData.findOne({ _id: req.params.id, user: req.userId });
    if (!waste)
      return res.status(404).json({ error: "Entry not found or not authorised" });

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

// Approve waste entry — marks as sold out, saves updated quantity
app.patch("/api/waste/approve/:id", verifyToken, async (req, res) => {
  try {
    const waste = await WasteData.findOne({ _id: req.params.id, user: req.userId });
    if (!waste)
      return res.status(404).json({ error: "Entry not found or not authorised" });

    waste.approved = true;
    if (req.body.foodQuantity !== undefined)
      waste.foodQuantity = req.body.foodQuantity;

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

// Create inventory item
app.post("/api/inventory", verifyToken, async (req, res) => {
  try {
    const item = new Inventory({ ...req.body, user: req.userId });
    await item.save();
    res.status(201).json(item);
  } catch (err) {
    res.status(500).json({ error: "Failed to save inventory item" });
  }
});

// Get all inventory for logged-in user
app.get("/api/inventory", verifyToken, async (req, res) => {
  try {
    res.json(await Inventory.find({ user: req.userId }));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch inventory" });
  }
});

// Update inventory item
app.patch("/api/inventory/:id", verifyToken, async (req, res) => {
  try {
    const item = await Inventory.findOneAndUpdate(
      { _id: req.params.id, user: req.userId },
      { $set: req.body },
      { new: true }
    );
    if (!item) return res.status(404).json({ error: "Item not found" });
    res.json(item);
  } catch (err) {
    res.status(500).json({ error: "Failed to update item" });
  }
});

// Delete inventory item
app.delete("/api/inventory/:id", verifyToken, async (req, res) => {
  try {
    const item = await Inventory.findOneAndDelete({ _id: req.params.id, user: req.userId });
    if (!item) return res.status(404).json({ error: "Item not found" });
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete item" });
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
  console.log(`🚀 FeedForward API running on port ${port}`);
});