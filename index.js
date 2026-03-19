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

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";
const MONGO_URI  = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/feedforward";

/* ═══════════════════════════════
   CORS
═══════════════════════════════ */
const allowedOrigins = [
  process.env.FRONTEND_URL,
  "http://localhost:3000",
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.log("CORS Blocked:", origin);
    callback(new Error("CORS blocked"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.options("*", cors(corsOptions));
app.use(cors(corsOptions));

/* ═══════════════════════════════
   SECURITY
═══════════════════════════════ */
app.use(helmet());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: (req) => req.method === "OPTIONS",
  standardHeaders: true,
  legacyHeaders: false,
}));

/* ═══════════════════════════════
   MIDDLEWARE
═══════════════════════════════ */
app.use(express.json());
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.url}`);
  next();
});
app.use("/uploads",     express.static(path.join(__dirname, "uploads")));
app.use("/api/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/api/recipes", recipeRoutes);

/* ═══════════════════════════════
   DATABASE
═══════════════════════════════ */
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => { console.error("❌ DB Error:", err.message); process.exit(1); });

/* ═══════════════════════════════
   HELPER — generate unique 5-char userId
   e.g. A3K9P, ZX72M
   No confusing chars: 0/O, 1/I excluded
═══════════════════════════════ */
const generateUserId = () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let id = "";
  for (let i = 0; i < 5; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
};

// Standalone helper — assigns a fresh unique userId to a user document
// Used both in the pre-save hook AND when backfilling existing users on login
const assignUserId = async (user) => {
  if (user.userId) return user.userId; // already has one
  let uid, exists;
  do {
    uid    = generateUserId();
    exists = await User.findOne({ userId: uid });
  } while (exists);
  user.userId = uid;
  await User.updateOne({ _id: user._id }, { $set: { userId: uid } });
  return uid;
};

/* ═══════════════════════════════
   MODELS
═══════════════════════════════ */
const UserSchema = new mongoose.Schema({
  userId:     { type: String, unique: true, sparse: true }, // sparse = allows null for old users
  username:   { type: String, required: true },
  email:      { type: String, unique: true, required: true },
  phone:      { type: String, default: "" },
  gender:     {
    type: String,
    enum: ["male", "female", "other", "prefer_not", ""],
    default: "",
  },
  password:   { type: String, required: true },
  resetToken: { type: String, default: null },
}, { timestamps: true });

// Pre-save hook: auto-generate userId for brand-new users
UserSchema.pre("save", async function (next) {
  if (this.userId) return next(); // already set, skip
  if (!this.isNew) return next(); // only for new documents
  let uid, exists;
  do {
    uid    = generateUserId();
    exists = await mongoose.model("User").findOne({ userId: uid });
  } while (exists);
  this.userId = uid;
  next();
});

const User = mongoose.model("User", UserSchema);

const WasteData = mongoose.model("WasteData", new mongoose.Schema({
  user:          { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  foodItem:      String,
  foodQuantity:  Number,
  foodReason:    String,
  foodWasteDate: { type: Date, default: Date.now },
  location:      String,
  image:         String,
  approved:      { type: Boolean, default: false },
}, { strict: false }));

const Inventory = mongoose.model("Inventory", new mongoose.Schema({
  user:             { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  itemName:         String,
  itemQuantity:     Number,
  itemCost:         Number,
  itemPurchaseDate: Date,
  itemExpiryDate:   Date,
  consumed:         { type: Boolean, default: false },
}));

/* ═══════════════════════════════
   MULTER + CLOUDINARY
═══════════════════════════════ */
let upload;
if (process.env.CLOUDINARY_CLOUD_NAME) {
  const cloudinary = require("cloudinary").v2;
  const { CloudinaryStorage } = require("multer-storage-cloudinary");
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key:    process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
  const cloudStorage = new CloudinaryStorage({
    cloudinary,
    params: {
      folder:          "feedforward",
      allowed_formats: ["jpg", "jpeg", "png", "webp", "gif"],
      transformation:  [{ width: 800, height: 800, crop: "limit", quality: "auto" }],
    },
  });
  upload = multer({ storage: cloudStorage, limits: { fileSize: 5 * 1024 * 1024 } });
  console.log("☁️  Cloudinary storage enabled");
} else {
  const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = "./uploads";
      if (!fs.existsSync(dir)) fs.mkdirSync(dir);
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    },
  });
  upload = multer({ storage: diskStorage, limits: { fileSize: 5 * 1024 * 1024 } });
  console.log("💾 Local disk storage");
}

/* ═══════════════════════════════
   JWT MIDDLEWARE
═══════════════════════════════ */
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

/* ═══════════════════════════════
   EMAIL
═══════════════════════════════ */
const sendPasswordResetEmail = async (email, token) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER || process.env.EMAIL,
      pass: process.env.EMAIL_PASS || process.env.EMAIL_PASSWORD,
    },
  });
  const url = `${process.env.FRONTEND_URL}/reset-password/${token}`;
  await transporter.sendMail({
    from: process.env.EMAIL_USER || process.env.EMAIL,
    to:   email,
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
          If you didn't request this, you can safely ignore this email.
        </p>
      </div>
    `,
  });
};

/* ═══════════════════════════════
   HEALTH
═══════════════════════════════ */
app.get("/", (req, res) => res.send("🚀 FeedForward API Running"));

app.get("/api/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

app.get("/api/refresh-token", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("_id email username");
    if (!user) return res.status(404).json({ error: "User not found" });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch { res.status(500).json({ error: "Could not refresh token" }); }
});

/* ═══════════════════════════════
   MIGRATION ROUTE
   GET /api/admin/backfill-userids
   One-time route: assigns userId to every
   existing user who doesn't have one yet.
   Call this ONCE from your browser after deploy:
   https://backend-food-fb9g.onrender.com/api/admin/backfill-userids
═══════════════════════════════ */
app.get("/api/admin/backfill-userids", async (req, res) => {
  try {
    // Find all users without a userId
    const users = await User.find({
      $or: [{ userId: { $exists: false } }, { userId: null }, { userId: "" }],
    });

    if (users.length === 0) {
      return res.json({ message: "All users already have a userId ✅", updated: 0 });
    }

    let updated = 0;
    for (const user of users) {
      let uid, exists;
      do {
        uid    = generateUserId();
        exists = await User.findOne({ userId: uid });
      } while (exists);
      await User.updateOne({ _id: user._id }, { $set: { userId: uid } });
      updated++;
      console.log(`✅ Assigned userId ${uid} to user ${user.email}`);
    }

    res.json({
      message: `✅ Backfilled ${updated} users with userId`,
      updated,
    });
  } catch (err) {
    console.error("Backfill error:", err);
    res.status(500).json({ error: "Backfill failed", details: err.message });
  }
});

/* ═══════════════════════════════
   AUTH ROUTES
═══════════════════════════════ */

// Register — saves gender, pre-save hook auto-generates userId
const handleRegister = async (req, res) => {
  try {
    const { username, email, password, phone, gender } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });
    if (password.length < 6)
      return res.status(400).json({ error: "Password too short (min 6 chars)" });
    if (await User.findOne({ email }))
      return res.status(409).json({ error: "Email already registered" });

    const hash    = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hash,
      phone:    phone   || "",
      gender:   gender  || "",
    });
    await newUser.save(); // pre-save hook assigns userId here

    res.status(201).json({
      message: "Registered successfully",
      userId:  newUser.userId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
};
app.post("/register",     handleRegister);
app.post("/api/register", handleRegister);

// Login — backfills userId if the user registered before this feature was added
const handleLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: "Invalid credentials" });

    // ── BACKFILL: if this is an old account with no userId, assign one now ──
    if (!user.userId) {
      await assignUserId(user);
      console.log(`✅ Backfilled userId for existing user: ${user.email} → ${user.userId}`);
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
};
app.post("/login",     handleLogin);
app.post("/api/login", handleLogin);

// Forgot Password
const handleForgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
    user.resetToken = token;
    await user.save();
    await sendPasswordResetEmail(user.email, token);
    res.json({ message: "Reset link sent to your email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to send reset email" });
  }
};
app.post("/forgot-password",     handleForgotPassword);
app.post("/api/forgot-password", handleForgotPassword);

// Reset Password
const handleResetPassword = async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, JWT_SECRET);
    const user    = await User.findById(decoded.userId);

    if (!user || user.resetToken !== req.params.token)
      return res.status(400).json({ error: "Invalid or expired token" });
    if (!req.body.password || req.body.password.length < 6)
      return res.status(400).json({ error: "Password too short (min 6 chars)" });

    user.password   = await bcrypt.hash(req.body.password, 10);
    user.resetToken = null;
    await user.save();
    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Reset failed" });
  }
};
app.post("/reset-password/:token",     handleResetPassword);
app.post("/api/reset-password/:token", handleResetPassword);

/* ═══════════════════════════════
   PROFILE ROUTES
═══════════════════════════════ */

// GET — returns logged-in user's full profile
// Also backfills userId on-the-fly if missing (covers old accounts)
app.get("/api/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password -resetToken");
    if (!user) return res.status(404).json({ error: "User not found" });

    // Backfill userId if this old account still doesn't have one
    if (!user.userId) {
      await assignUserId(user);
      console.log(`✅ Profile fetch: backfilled userId for ${user.email} → ${user.userId}`);
    }

    // Re-fetch so the response includes the newly assigned userId
    const fresh = await User.findById(req.userId).select("-password -resetToken");
    res.json(fresh);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// PUT — update username, phone, gender (email & userId are immutable)
app.put("/api/profile", verifyToken, async (req, res) => {
  try {
    const { username, phone, gender } = req.body;

    if (!username || username.trim().length < 2)
      return res.status(400).json({ error: "Username must be at least 2 characters" });

    const allowedGenders = ["male", "female", "other", "prefer_not", ""];
    if (gender !== undefined && !allowedGenders.includes(gender))
      return res.status(400).json({ error: "Invalid gender value" });

    const updated = await User.findByIdAndUpdate(
      req.userId,
      {
        username: username.trim(),
        phone:    (phone  || "").trim(),
        gender:   gender  || "",
      },
      { new: true, runValidators: true }
    ).select("-password -resetToken");

    if (!updated) return res.status(404).json({ error: "User not found" });
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

/* ═══════════════════════════════
   WASTE — COMMUNITY FEED
   GET /waste/feed  +  /api/waste/feed
   Returns ALL users' entries — no userId filter.
   Used by Display.jsx to show everyone's donations.
   MUST be registered BEFORE /api/waste to avoid
   Express matching /api/waste first.
═══════════════════════════════ */
const handleGetFeed = async (req, res) => {
  try {
    const data = await WasteData.find({})
      .sort({ foodWasteDate: -1 })
      .limit(500)
      .populate("user", "username userId phone");

    const normalized = data.map(item => {
      const obj = item.toObject();
      if (obj.approved === undefined || obj.approved === null) obj.approved = false;
      return obj;
    });

    res.json(normalized);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch community feed" });
  }
};
app.get("/waste/feed",     verifyToken, handleGetFeed);
app.get("/api/waste/feed", verifyToken, handleGetFeed);

/* ═══════════════════════════════
   WASTE — MY ENTRIES ONLY
   GET /waste  +  /api/waste
   Returns only the logged-in user's entries.
   Used by Waste.jsx form page & Profile stats.
═══════════════════════════════ */
const handleGetWaste = async (req, res) => {
  try {
    const data = await WasteData.find({ user: req.userId }).sort({ foodWasteDate: -1 });
    const normalized = data.map(item => {
      const obj = item.toObject();
      if (obj.approved === undefined || obj.approved === null) obj.approved = false;
      return obj;
    });
    res.json(normalized);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch waste data" });
  }
};
app.get("/waste",     verifyToken, handleGetWaste);
app.get("/api/waste", verifyToken, handleGetWaste);

// Create
const handleCreateWaste = async (req, res) => {
  try {
    const { foodItem, foodQuantity, foodReason, foodWasteDate, location } = req.body;
    if (!foodItem || !foodQuantity || !foodReason || !foodWasteDate || !location)
      return res.status(400).json({ error: "All fields are required" });

    const waste = new WasteData({
      user: req.userId,
      foodItem, foodQuantity, foodReason, foodWasteDate, location,
      image: req.file ? (req.file.path || req.file.filename) : null,
    });
    await waste.save();

    // Return populated so frontend immediately gets donor info
    const populated = await WasteData.findById(waste._id).populate("user", "username userId phone");
    res.status(201).json(populated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save waste entry" });
  }
};
app.post("/waste",     verifyToken, upload.single("image"), handleCreateWaste);
app.post("/api/waste", verifyToken, upload.single("image"), handleCreateWaste);

// Delete
const handleDeleteWaste = async (req, res) => {
  try {
    const waste = await WasteData.findOne({ _id: req.params.id, user: req.userId });
    if (!waste) return res.status(404).json({ error: "Waste item not found" });

    if (waste.image && !waste.image.startsWith("http")) {
      const imgPath = path.join(__dirname, "uploads", waste.image);
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }
    await waste.deleteOne();
    res.json({ message: `"${waste.foodItem}" deleted successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete waste item" });
  }
};
app.delete("/waste/:id",     verifyToken, handleDeleteWaste);
app.delete("/api/waste/:id", verifyToken, handleDeleteWaste);

// Approve
const handleApproveWaste = async (req, res) => {
  try {
    const waste = await WasteData.findOne({ _id: req.params.id, user: req.userId });
    if (!waste) return res.status(404).json({ error: "Waste item not found" });
    if (waste.approved) return res.status(400).json({ error: "Already approved" });

    waste.approved     = true;
    waste.foodQuantity = req.body.foodQuantity !== undefined
      ? req.body.foodQuantity
      : Math.floor(waste.foodQuantity * 0.9);
    await waste.save();
    res.json({ message: "Food item approved", data: waste });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Approval failed" });
  }
};
app.patch("/waste/approve/:id",     verifyToken, handleApproveWaste);
app.patch("/api/waste/approve/:id", verifyToken, handleApproveWaste);

/* ═══════════════════════════════
   INVENTORY ROUTES
═══════════════════════════════ */

// Create
const handleCreateInventory = async (req, res) => {
  try {
    const { itemName, itemQuantity, itemCost, itemPurchaseDate, itemExpiryDate } = req.body;
    if (!itemName || !itemQuantity || !itemCost || !itemPurchaseDate || !itemExpiryDate)
      return res.status(400).json({ error: "All fields are required" });

    const item = new Inventory({
      user: req.userId,
      itemName, itemQuantity, itemCost,
      itemPurchaseDate, itemExpiryDate,
      consumed: false,
    });
    await item.save();
    res.status(201).json(item);
  } catch (err) {
    res.status(500).json({ error: "Failed to add inventory item" });
  }
};
app.post("/inventory",     verifyToken, handleCreateInventory);
app.post("/api/inventory", verifyToken, handleCreateInventory);

// Read
const handleGetInventory = async (req, res) => {
  try {
    res.json(await Inventory.find({ user: req.userId }));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch inventory" });
  }
};
app.get("/inventory",     verifyToken, handleGetInventory);
app.get("/api/inventory", verifyToken, handleGetInventory);

// Update quantity
const handleUpdateInventory = async (req, res) => {
  try {
    const item = await Inventory.findOne({ _id: req.params.id, user: req.userId });
    if (!item) return res.status(404).json({ error: "Inventory item not found" });
    if (req.body.itemQuantity !== undefined) item.itemQuantity = req.body.itemQuantity;
    await item.save();
    res.json({ message: "Inventory item updated", data: item });
  } catch (err) {
    res.status(500).json({ error: "Failed to update inventory item" });
  }
};
app.patch("/inventory/:id",     verifyToken, handleUpdateInventory);
app.patch("/api/inventory/:id", verifyToken, handleUpdateInventory);

// Delete
const handleDeleteInventory = async (req, res) => {
  try {
    const item = await Inventory.findOneAndDelete({ _id: req.params.id, user: req.userId });
    if (!item) return res.status(404).json({ error: "Inventory item not found" });
    res.json({ message: `"${item.itemName}" deleted successfully` });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete inventory item" });
  }
};
app.delete("/inventory/:id",     verifyToken, handleDeleteInventory);
app.delete("/api/inventory/:id", verifyToken, handleDeleteInventory);

// Approve / consume
const handleApproveInventory = async (req, res) => {
  try {
    const item = await Inventory.findOne({ _id: req.params.id, user: req.userId });
    if (!item) return res.status(404).json({ error: "Inventory item not found" });
    if (item.consumed) return res.status(400).json({ error: "Already consumed" });
    item.consumed = true;
    await item.save();
    res.json({ message: "Inventory item consumed", data: item });
  } catch (err) {
    res.status(500).json({ error: "Failed to approve inventory item" });
  }
};
app.patch("/inventory/approve/:id",     verifyToken, handleApproveInventory);
app.patch("/api/inventory/approve/:id", verifyToken, handleApproveInventory);

/* ═══════════════════════════════
   RESERVATION MODEL
   Each document = one person reserving one food item.
   - reserverName, reserverPhone, reserverEmail  : contact info
   - foodItem (WasteData _id)                    : which item
   - quantity                                    : always 1
   - code                                        : 6-char pickup code (expires 24h)
   - codeExpiresAt                               : 24h from creation
   - collected                                   : donor marks true on pickup
═══════════════════════════════ */
const ReservationSchema = new mongoose.Schema({
  foodItem:      { type: mongoose.Schema.Types.ObjectId, ref: "WasteData", required: true },
  reserverName:  { type: String, required: true },
  reserverPhone: { type: String, required: true },
  reserverEmail: { type: String, required: true },
  quantity:      { type: Number, default: 1, min: 1, max: 1 },
  code:          { type: String, required: true, unique: true },
  codeExpiresAt: { type: Date, required: true },
  collected:     { type: Boolean, default: false },
}, { timestamps: true });

const Reservation = mongoose.model("Reservation", ReservationSchema);

/* ── generate 6-char alphanumeric pickup code ── */
const generateCode = () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
};

/* ═══════════════════════════════
   RESERVATION ROUTES
═══════════════════════════════ */

// POST /api/reservations — make a reservation
// Rules:
//  • quantity locked to 1
//  • same phone/email cannot reserve same food item twice
//  • if total reservations >= foodQuantity → auto sold out
const handleCreateReservation = async (req, res) => {
  try {
    const { foodItemId, reserverName, reserverPhone, reserverEmail } = req.body;

    if (!foodItemId || !reserverName || !reserverPhone || !reserverEmail)
      return res.status(400).json({ error: "Name, phone, email and food item are required." });

    // Validate email format
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reserverEmail))
      return res.status(400).json({ error: "Invalid email address." });

    // Validate phone (min 7 digits)
    if (!/^\+?[\d\s\-]{7,15}$/.test(reserverPhone))
      return res.status(400).json({ error: "Invalid phone number." });

    // Find the food item
    const food = await WasteData.findById(foodItemId);
    if (!food)
      return res.status(404).json({ error: "Food item not found." });
    if (food.approved)
      return res.status(400).json({ error: "This item is already sold out." });

    // Check if this person already reserved this item (by phone OR email)
    const alreadyReserved = await Reservation.findOne({
      foodItem: foodItemId,
      $or: [
        { reserverPhone: reserverPhone.trim() },
        { reserverEmail: reserverEmail.trim().toLowerCase() },
      ],
    });
    if (alreadyReserved)
      return res.status(409).json({ error: "You have already reserved this item. You can reserve a different food item." });

    // Count existing reservations for this item
    const existingCount = await Reservation.countDocuments({ foodItem: foodItemId });
    const totalQty      = Number(food.foodQuantity) || 1;

    if (existingCount >= totalQty)
      return res.status(400).json({ error: "Sorry, this item is fully reserved and no longer available." });

    // Generate unique pickup code
    let code, codeExists;
    do {
      code      = generateCode();
      codeExists = await Reservation.findOne({ code });
    } while (codeExists);

    // Code expires 24 hours from now
    const codeExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const reservation = await Reservation.create({
      foodItem:      foodItemId,
      reserverName:  reserverName.trim(),
      reserverPhone: reserverPhone.trim(),
      reserverEmail: reserverEmail.trim().toLowerCase(),
      quantity:      1,
      code,
      codeExpiresAt,
      collected:     false,
    });

    // Check if this reservation fills up the item → auto sold out
    const newCount = existingCount + 1;
    if (newCount >= totalQty) {
      food.approved = true;
      await food.save();
      console.log(`✅ Auto sold-out: ${food.foodItem} (${newCount}/${totalQty} reserved)`);
    }

    res.status(201).json({
      message:       "Reservation confirmed!",
      code,
      codeExpiresAt,
      reservationId: reservation._id,
      foodItem:      food.foodItem,
      location:      food.location,
      spotsLeft:     Math.max(0, totalQty - newCount),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create reservation." });
  }
};
app.post("/reservations",     handleCreateReservation);
app.post("/api/reservations", handleCreateReservation);

// GET /api/reservations/food/:foodItemId — get reservation count for a food item (public, no auth needed)
const handleGetReservationCount = async (req, res) => {
  try {
    const food  = await WasteData.findById(req.params.foodItemId);
    if (!food) return res.status(404).json({ error: "Food item not found." });

    const count    = await Reservation.countDocuments({ foodItem: req.params.foodItemId });
    const totalQty = Number(food.foodQuantity) || 1;
    const spotsLeft = Math.max(0, totalQty - count);

    res.json({
      reserved:   count,
      total:      totalQty,
      spotsLeft,
      isSoldOut:  food.approved || spotsLeft === 0,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch reservation count." });
  }
};
app.get("/reservations/food/:foodItemId",     handleGetReservationCount);
app.get("/api/reservations/food/:foodItemId", handleGetReservationCount);

// POST /api/reservations/collect — donor verifies pickup code
// Body: { code }
const handleCollect = async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Pickup code is required." });

    const reservation = await Reservation.findOne({ code: code.trim().toUpperCase() })
      .populate("foodItem", "foodItem location");

    if (!reservation)
      return res.status(404).json({ error: "Invalid code. No reservation found." });

    if (reservation.collected)
      return res.status(400).json({ error: "This code has already been used for collection." });

    // Check expiry (24h)
    if (new Date() > reservation.codeExpiresAt)
      return res.status(400).json({ error: "This pickup code has expired (24h limit)." });

    reservation.collected = true;
    await reservation.save();

    res.json({
      message:      "✅ Collection verified! Food handed over.",
      reserverName: reservation.reserverName,
      reserverPhone: reservation.reserverPhone,
      foodItem:     reservation.foodItem?.foodItem,
      location:     reservation.foodItem?.location,
      collectedAt:  new Date(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to verify code." });
  }
};
app.post("/reservations/collect",     verifyToken, handleCollect);
app.post("/api/reservations/collect", verifyToken, handleCollect);

// GET /api/reservations/my — get reservations made by current user's phone/email
// Used so user can see their active reservations (optional, nice-to-have)
app.get("/api/reservations/my", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("email phone");
    if (!user) return res.status(404).json({ error: "User not found." });

    const reservations = await Reservation.find({
      $or: [
        { reserverEmail: user.email },
        ...(user.phone ? [{ reserverPhone: user.phone }] : []),
      ],
    })
      .populate("foodItem", "foodItem location foodWasteDate image")
      .sort({ createdAt: -1 });

    res.json(reservations);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch your reservations." });
  }
});

/* ═══════════════════════════════
   GLOBAL ERROR HANDLER
═══════════════════════════════ */
app.use((err, req, res, next) => {
  console.error("❌ Error:", err.message);
  if (err.message === "CORS blocked")
    return res.status(403).json({ error: "CORS blocked" });
  res.status(500).json({ error: "Internal server error" });
});

/* ═══════════════════════════════
   START
═══════════════════════════════ */
app.listen(port, () => {
  console.log(`🚀 FeedForward API running on port ${port}`);
});