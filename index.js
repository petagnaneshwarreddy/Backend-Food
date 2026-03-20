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
═══════════════════════════════ */
const generateUserId = () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let id = "";
  for (let i = 0; i < 5; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
};

const assignUserId = async (user) => {
  if (user.userId) return user.userId;
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
  userId:   { type: String, unique: true, sparse: true },
  username: { type: String, required: true },
  email:    { type: String, unique: true, required: true },
  phone:    { type: String, default: "" },
  gender:   {
    type: String,
    enum: ["male", "female", "other", "prefer_not", ""],
    default: "",
  },
  password: { type: String, required: true },

  /* ★ NEW — role: "donor" (default) or "recipient" */
  role: {
    type:    String,
    enum:    ["donor", "recipient"],
    default: "donor",
  },

  /* ★ NEW — location captured at signup */
  location: { type: String, default: "" },

  resetToken: { type: String, default: null },
}, { timestamps: true });

UserSchema.pre("save", async function (next) {
  if (this.userId) return next();
  if (!this.isNew) return next();
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
   ★ req.role now available on every protected route
═══════════════════════════════ */
const verifyToken = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer "))
    return res.status(401).json({ error: "Unauthorized - No token" });
  const token = header.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.userId = decoded.userId;
    req.role   = decoded.role || "donor"; // ★
    next();
  });
};

/* ★ Middleware — blocks recipients from donor-only routes */
const guardDonor = (req, res, next) => {
  if (req.role === "recipient")
    return res.status(403).json({ error: "This feature is only available for donors." });
  next();
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

/* ★ refresh-token — includes role + username in new token */
app.get("/api/refresh-token", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("_id email username role");
    if (!user) return res.status(404).json({ error: "User not found" });
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role || "donor" },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.json({ token, role: user.role || "donor" });
  } catch { res.status(500).json({ error: "Could not refresh token" }); }
});

/* ═══════════════════════════════
   MIGRATION ROUTES
═══════════════════════════════ */
app.get("/api/admin/backfill-userids", async (req, res) => {
  try {
    const users = await User.find({
      $or: [{ userId: { $exists: false } }, { userId: null }, { userId: "" }],
    });

    if (users.length === 0)
      return res.json({ message: "All users already have a userId ✅", updated: 0 });

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

    res.json({ message: `✅ Backfilled ${updated} users with userId`, updated });
  } catch (err) {
    console.error("Backfill error:", err);
    res.status(500).json({ error: "Backfill failed", details: err.message });
  }
});

/* ★ NEW — set role="donor" for all existing users who have no role */
app.get("/api/admin/backfill-roles", async (req, res) => {
  try {
    const result = await User.updateMany(
      { $or: [{ role: { $exists: false } }, { role: null }, { role: "" }] },
      { $set: { role: "donor" } }
    );
    res.json({
      message: `✅ Backfilled role=donor for ${result.modifiedCount} users`,
      updated: result.modifiedCount,
    });
  } catch (err) {
    console.error("Role backfill error:", err);
    res.status(500).json({ error: "Role backfill failed", details: err.message });
  }
});

/* ═══════════════════════════════
   AUTH ROUTES
═══════════════════════════════ */

/* ★ REGISTER — now accepts role + location */
const handleRegister = async (req, res) => {
  try {
    const { username, email, password, phone, gender, role, location } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });
    if (password.length < 6)
      return res.status(400).json({ error: "Password too short (min 6 chars)" });
    if (await User.findOne({ email }))
      return res.status(409).json({ error: "Email already registered" });

    /* Validate role — only allow known values, default to "donor" */
    const validRole = ["donor", "recipient"].includes(role) ? role : "donor";

    const hash    = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hash,
      phone:    phone    || "",
      gender:   gender   || "",
      role:     validRole,       // ★
      location: location || "",  // ★
    });
    await newUser.save();

    console.log(`✅ Registered: ${email} as ${validRole}`);
    res.status(201).json({
      message: "Registered successfully",
      userId:  newUser.userId,
      role:    validRole, // ★ return so frontend can cache immediately
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
};
app.post("/register",     handleRegister);
app.post("/api/register", handleRegister);

/* ★ LOGIN — role + username now in JWT payload */
const handleLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: "Invalid credentials" });

    /* Backfill userId for old accounts */
    if (!user.userId) {
      await assignUserId(user);
      console.log(`✅ Backfilled userId for existing user: ${user.email} → ${user.userId}`);
    }

    /* ★ Backfill role for old accounts — default to "donor" */
    if (!user.role) {
      user.role = "donor";
      await User.updateOne({ _id: user._id }, { $set: { role: "donor" } });
      console.log(`✅ Backfilled role=donor for: ${user.email}`);
    }

    /* ★ role + username included in JWT — no extra API call needed */
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      role:     user.role,      // ★
      username: user.username,  // ★
      userId:   user.userId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
};
app.post("/login",     handleLogin);
app.post("/api/login", handleLogin);

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
   ★ Returns role + location
═══════════════════════════════ */
app.get("/api/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password -resetToken");
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!user.userId) {
      await assignUserId(user);
      console.log(`✅ Profile fetch: backfilled userId for ${user.email} → ${user.userId}`);
    }

    /* ★ Backfill role for old accounts */
    if (!user.role) {
      await User.updateOne({ _id: user._id }, { $set: { role: "donor" } });
    }

    const fresh = await User.findById(req.userId).select("-password -resetToken");
    res.json(fresh); // ★ includes role + location
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

/* ★ PUT /api/profile — accepts location now */
app.put("/api/profile", verifyToken, async (req, res) => {
  try {
    const { username, phone, gender, location } = req.body;

    if (!username || username.trim().length < 2)
      return res.status(400).json({ error: "Username must be at least 2 characters" });

    const allowedGenders = ["male", "female", "other", "prefer_not", ""];
    if (gender !== undefined && !allowedGenders.includes(gender))
      return res.status(400).json({ error: "Invalid gender value" });

    const updated = await User.findByIdAndUpdate(
      req.userId,
      {
        username: username.trim(),
        phone:    (phone    || "").trim(),
        gender:   gender    || "",
        location: (location || "").trim(), // ★
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
   NOTE: must be registered BEFORE /api/waste
═══════════════════════════════ */
const handleGetFeed = async (req, res) => {
  try {
    const data = await WasteData.find({})
      .sort({ foodWasteDate: -1 })
      .limit(500)
      .populate("user", "username userId phone email");

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

/* ★ CREATE WASTE — recipients cannot post donations */
const handleCreateWaste = async (req, res) => {
  try {
    if (req.role === "recipient")
      return res.status(403).json({ error: "Recipients cannot post food donations. Please register as a donor." });

    const { foodItem, foodQuantity, foodReason, foodWasteDate, location } = req.body;
    if (!foodItem || !foodQuantity || !foodReason || !foodWasteDate || !location)
      return res.status(400).json({ error: "All fields are required" });

    const waste = new WasteData({
      user: req.userId,
      foodItem, foodQuantity, foodReason, foodWasteDate, location,
      image: req.file ? (req.file.path || req.file.filename) : null,
    });
    await waste.save();

    const populated = await WasteData.findById(waste._id)
      .populate("user", "username userId phone email");
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
   ★ guardDonor — recipients blocked from all inventory routes
═══════════════════════════════ */
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
app.post("/inventory",     verifyToken, guardDonor, handleCreateInventory);
app.post("/api/inventory", verifyToken, guardDonor, handleCreateInventory);

const handleGetInventory = async (req, res) => {
  try {
    res.json(await Inventory.find({ user: req.userId }));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch inventory" });
  }
};
app.get("/inventory",     verifyToken, guardDonor, handleGetInventory);
app.get("/api/inventory", verifyToken, guardDonor, handleGetInventory);

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
app.patch("/inventory/:id",     verifyToken, guardDonor, handleUpdateInventory);
app.patch("/api/inventory/:id", verifyToken, guardDonor, handleUpdateInventory);

const handleDeleteInventory = async (req, res) => {
  try {
    const item = await Inventory.findOneAndDelete({ _id: req.params.id, user: req.userId });
    if (!item) return res.status(404).json({ error: "Inventory item not found" });
    res.json({ message: `"${item.itemName}" deleted successfully` });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete inventory item" });
  }
};
app.delete("/inventory/:id",     verifyToken, guardDonor, handleDeleteInventory);
app.delete("/api/inventory/:id", verifyToken, guardDonor, handleDeleteInventory);

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
app.patch("/inventory/approve/:id",     verifyToken, guardDonor, handleApproveInventory);
app.patch("/api/inventory/approve/:id", verifyToken, guardDonor, handleApproveInventory);

/* ═══════════════════════════════
   RESERVATION MODEL
   ─────────────────────────────
   collected   = true when donor physically hands food over
   pickedUpAt  = timestamp of that moment
   reserverId  = ★ NEW links to the User who reserved
═══════════════════════════════ */
const ReservationSchema = new mongoose.Schema({
  foodItem:      { type: mongoose.Schema.Types.ObjectId, ref: "WasteData", required: true },
  reserverName:  { type: String, required: true },
  reserverPhone: { type: String, required: true },
  reserverEmail: { type: String, required: true },
  reserverId:    { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }, // ★ NEW
  quantity:      { type: Number, default: 1, min: 1, max: 1 },
  code:          { type: String, required: true, unique: true },
  codeExpiresAt: { type: Date, required: true },
  collected:     { type: Boolean, default: false },
  pickedUpAt:    { type: Date, default: null },
}, { timestamps: true });

const Reservation = mongoose.model("Reservation", ReservationSchema);

const generateCode = () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
};

/* ═══════════════════════════════
   RESERVATION ROUTES
═══════════════════════════════ */

// POST /api/reservations — ★ saves reserverId
const handleCreateReservation = async (req, res) => {
  try {
    const { foodItemId, reserverName, reserverPhone, reserverEmail } = req.body;

    if (!foodItemId || !reserverName || !reserverPhone || !reserverEmail)
      return res.status(400).json({ error: "Name, phone, email and food item are required." });

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reserverEmail))
      return res.status(400).json({ error: "Invalid email address." });

    if (!/^\+?[\d\s\-]{7,15}$/.test(reserverPhone))
      return res.status(400).json({ error: "Invalid phone number." });

    const food = await WasteData.findById(foodItemId)
      .populate("user", "username userId phone email");
    if (!food)
      return res.status(404).json({ error: "Food item not found." });
    if (food.approved)
      return res.status(400).json({ error: "This item is already sold out." });

    const alreadyReserved = await Reservation.findOne({
      foodItem: foodItemId,
      $or: [
        { reserverPhone: reserverPhone.trim() },
        { reserverEmail: reserverEmail.trim().toLowerCase() },
      ],
    });
    if (alreadyReserved)
      return res.status(409).json({ error: "You have already reserved this item. You can reserve a different food item." });

    const existingCount = await Reservation.countDocuments({ foodItem: foodItemId });
    const totalQty      = Number(food.foodQuantity) || 1;

    if (existingCount >= totalQty)
      return res.status(400).json({ error: "Sorry, this item is fully reserved and no longer available." });

    let code, codeExists;
    do {
      code       = generateCode();
      codeExists = await Reservation.findOne({ code });
    } while (codeExists);

    const codeExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const reservation = await Reservation.create({
      foodItem:      foodItemId,
      reserverName:  reserverName.trim(),
      reserverPhone: reserverPhone.trim(),
      reserverEmail: reserverEmail.trim().toLowerCase(),
      reserverId:    req.userId || null, // ★
      quantity:      1,
      code,
      codeExpiresAt,
      collected:     false,
      pickedUpAt:    null,
    });

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
      foodQuantity:  food.foodQuantity,
      foodReason:    food.foodReason,
      foodWasteDate: food.foodWasteDate,
      location:      food.location,
      spotsLeft:     Math.max(0, totalQty - newCount),
      donor: {
        name:   food.user?.username || "Anonymous",
        phone:  food.user?.phone    || null,
        email:  food.user?.email    || null,
        userId: food.user?.userId   || null,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create reservation." });
  }
};
app.post("/reservations",     handleCreateReservation);
app.post("/api/reservations", handleCreateReservation);

// GET /api/reservations/food/:foodItemId
const handleGetReservationCount = async (req, res) => {
  try {
    const food = await WasteData.findById(req.params.foodItemId);
    if (!food) return res.status(404).json({ error: "Food item not found." });

    const totalQty = Number(food.foodQuantity) || 1;

    const reserved = await Reservation.countDocuments({ foodItem: req.params.foodItemId });
    const pickedUp = await Reservation.countDocuments({ foodItem: req.params.foodItemId, collected: true });

    const spotsLeft = Math.max(0, totalQty - reserved);
    const isSoldOut = food.approved || spotsLeft === 0;

    res.json({ reserved, pickedUp, total: totalQty, spotsLeft, isSoldOut });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch reservation count." });
  }
};
app.get("/reservations/food/:foodItemId",     handleGetReservationCount);
app.get("/api/reservations/food/:foodItemId", handleGetReservationCount);

// ─────────────────────────────────────────────────────────────
// POST /api/reservations/verify-pickup   ★ NEW
//
// Called by the DONOR in Waste.jsx when a collector arrives
// and shows their 6-char code.
//
// Body:   { code: "D38N89", foodItemId?: "..." }
//
// Logic:
//  1. Find reservation by code (case-insensitive)
//  2. If foodItemId provided, verify code belongs to that item
//  3. Reject if already collected (409)
//  4. Reject if expired (410)
//  5. Mark collected=true, pickedUpAt=now
//  6. Recount pickedUp for that food item
//  7. Auto sold-out if all spots physically picked up
//
// Response:
//  { success, message, foodItem, itemId,
//    spotsLeft, total, pickedUp, isSoldOut,
//    reserverName, reserverPhone, pickedUpAt }
// ─────────────────────────────────────────────────────────────
const handleVerifyPickup = async (req, res) => {
  try {
    const { code, foodItemId } = req.body;

    if (!code)
      return res.status(400).json({ error: "Pickup code is required." });

    const reservation = await Reservation.findOne({
      code: code.trim().toUpperCase(),
    }).populate("foodItem", "foodItem foodQuantity location approved");

    if (!reservation)
      return res.status(404).json({ error: "Invalid or expired code." });

    if (foodItemId) {
      const resItemId = (reservation.foodItem?._id || reservation.foodItem).toString();
      if (resItemId !== foodItemId.toString())
        return res.status(404).json({ error: "Invalid or expired code." });
    }

    if (reservation.collected)
      return res.status(409).json({ error: "This code has already been used for pickup." });

    if (new Date() > new Date(reservation.codeExpiresAt))
      return res.status(410).json({ error: "This pickup code has expired (24h limit)." });

    reservation.collected  = true;
    reservation.pickedUpAt = new Date();
    await reservation.save();

    const food          = reservation.foodItem;
    const itemId        = food._id;
    const totalQty      = Number(food.foodQuantity) || 1;
    const totalReserved = await Reservation.countDocuments({ foodItem: itemId });
    const pickedUpCount = await Reservation.countDocuments({ foodItem: itemId, collected: true });
    const spotsLeft     = Math.max(0, totalQty - totalReserved);
    const isSoldOut     = food.approved || spotsLeft === 0 || pickedUpCount >= totalQty;

    if (isSoldOut && !food.approved) {
      await WasteData.findByIdAndUpdate(itemId, { approved: true });
      console.log(`✅ Auto sold-out after pickup: "${food.foodItem}" (${pickedUpCount}/${totalQty} picked up)`);
    }

    console.log(`✅ Pickup verified: code=${code.toUpperCase()} item="${food.foodItem}" collector="${reservation.reserverName}"`);

    res.status(200).json({
      success:       true,
      message:       "Pickup confirmed! Food handed over successfully.",
      foodItem:      food.foodItem,
      itemId,
      spotsLeft,
      total:         totalQty,
      pickedUp:      pickedUpCount,
      isSoldOut,
      reserverName:  reservation.reserverName,
      reserverPhone: reservation.reserverPhone,
      pickedUpAt:    reservation.pickedUpAt,
    });
  } catch (err) {
    console.error("verify-pickup error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
};
app.post("/reservations/verify-pickup",     verifyToken, handleVerifyPickup);
app.post("/api/reservations/verify-pickup", verifyToken, handleVerifyPickup);

// ─────────────────────────────────────────────────────────────
// POST /api/reservations/collect   (legacy alias — same logic)
// ─────────────────────────────────────────────────────────────
const handleCollect = async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Pickup code is required." });

    const reservation = await Reservation.findOne({ code: code.trim().toUpperCase() })
      .populate("foodItem", "foodItem location foodQuantity approved");

    if (!reservation)
      return res.status(404).json({ error: "Invalid code. No reservation found." });
    if (reservation.collected)
      return res.status(409).json({ error: "This code has already been used for collection." });
    if (new Date() > reservation.codeExpiresAt)
      return res.status(410).json({ error: "This pickup code has expired (24h limit)." });

    reservation.collected  = true;
    reservation.pickedUpAt = new Date();
    await reservation.save();

    const food          = reservation.foodItem;
    const itemId        = food._id;
    const totalQty      = Number(food.foodQuantity) || 1;
    const totalReserved = await Reservation.countDocuments({ foodItem: itemId });
    const pickedUpCount = await Reservation.countDocuments({ foodItem: itemId, collected: true });
    const spotsLeft     = Math.max(0, totalQty - totalReserved);

    if ((spotsLeft === 0 || pickedUpCount >= totalQty) && !food.approved) {
      await WasteData.findByIdAndUpdate(itemId, { approved: true });
    }

    res.json({
      message:       "✅ Collection verified! Food handed over.",
      reserverName:  reservation.reserverName,
      reserverPhone: reservation.reserverPhone,
      foodItem:      food?.foodItem,
      itemId,
      location:      food?.location,
      spotsLeft,
      pickedUp:      pickedUpCount,
      isSoldOut:     food.approved || spotsLeft === 0,
      collectedAt:   reservation.pickedUpAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to verify code." });
  }
};
app.post("/reservations/collect",     verifyToken, handleCollect);
app.post("/api/reservations/collect", verifyToken, handleCollect);

// GET /api/reservations/my — ★ now queries by reserverId too
app.get("/api/reservations/my", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("email phone");
    if (!user) return res.status(404).json({ error: "User not found." });

    const reservations = await Reservation.find({
      $or: [
        { reserverId:    req.userId },  // ★ primary
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
   NOTIFICATION MODEL
═══════════════════════════════ */
const NotificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title:     { type: String, required: true },
  message:   { type: String, required: true },
  code:      { type: String, default: null },
  read:      { type: Boolean, default: false },
  type:      { type: String, default: "code_resend" },
}, { timestamps: true });

const Notification = mongoose.model("Notification", NotificationSchema);

/* ═══════════════════════════════
   NOTIFICATION ROUTES
═══════════════════════════════ */
app.get("/api/notifications", verifyToken, async (req, res) => {
  try {
    const notifs = await Notification.find({ recipient: req.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(notifs);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch notifications." });
  }
});

app.patch("/api/notifications/read-all", verifyToken, async (req, res) => {
  try {
    await Notification.updateMany({ recipient: req.userId, read: false }, { $set: { read: true } });
    res.json({ message: "All notifications marked as read." });
  } catch (err) {
    res.status(500).json({ error: "Failed to mark notifications as read." });
  }
});

app.patch("/api/notifications/:id/read", verifyToken, async (req, res) => {
  try {
    await Notification.findOneAndUpdate(
      { _id: req.params.id, recipient: req.userId },
      { $set: { read: true } }
    );
    res.json({ message: "Notification marked as read." });
  } catch (err) {
    res.status(500).json({ error: "Failed to mark notification as read." });
  }
});

/* ─────────────────────────────────────────────────────────────
   POST /api/reservations/resend-code
   Called by a COLLECTOR who forgot their pickup code.

   Body: { reserverName: "Ravi Kumar" }

   Flow:
   1. Find active (not collected, not expired) reservation by name
   2. Find the food item → get the donor (food.user)
   3. Create a Notification for the donor showing the code
   4. Donor sees it in their bell → tells collector verbally

   Returns: { message, donorName }
─────────────────────────────────────────────────────────────── */
const handleResendCode = async (req, res) => {
  try {
    const { reserverName } = req.body;
    if (!reserverName || reserverName.trim().length < 2)
      return res.status(400).json({ error: "Please provide your full name as used when reserving." });

    const name = reserverName.trim();

    const reservation = await Reservation.findOne({
      reserverName:  { $regex: new RegExp(`^${name}$`, "i") },
      collected:     false,
      codeExpiresAt: { $gt: new Date() },
    })
      .populate({
        path: "foodItem",
        populate: { path: "user", select: "username _id" },
      })
      .sort({ createdAt: -1 });

    if (!reservation)
      return res.status(404).json({
        error: `No active reservation found for "${name}". Please check the spelling of your name, or contact the donor directly.`,
      });

    const food  = reservation.foodItem;
    const donor = food?.user;

    if (!donor)
      return res.status(404).json({ error: "Could not find the donor for this reservation." });

    await Notification.create({
      recipient: donor._id,
      title:     "📦 Code Resend Request",
      message:   `${reservation.reserverName} forgot their pickup code for "${food?.foodItem || "your item"}". Their code is shown below — please tell them verbally.`,
      code:      reservation.code,
      type:      "code_resend",
      read:      false,
    });

    console.log(`✅ Code resend: notification sent to donor ${donor.username} for collector ${name}`);

    res.json({
      message:   `✓ Done! ${donor.username || "The donor"} has been notified. Ask them to check their notification bell and read your code to you.`,
      donorName: donor.username || "the donor",
    });
  } catch (err) {
    console.error("resend-code error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
};
app.post("/reservations/resend-code",     verifyToken, handleResendCode);
app.post("/api/reservations/resend-code", verifyToken, handleResendCode);

/* ─────────────────────────────────────────────────────────────
   GET /api/reservations/search-by-user
   Collector forgot code → searches by userId or phone →
   returns their active (not collected, not expired) reservations
   so they can pick which item to resend the code for.

   Query: ?q=PXXX7  OR  ?q=9876543210
─────────────────────────────────────────────────────────────── */
app.get("/api/reservations/search-by-user", verifyToken, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length < 3)
      return res.status(400).json({ error: "Please provide a User ID or phone number (min 3 chars)." });

    const query = q.trim();

    const user = await User.findOne({
      $or: [
        { userId: { $regex: new RegExp(`^${query}$`, "i") } },
        { phone:  query },
        { phone:  { $regex: query } },
      ],
    }).select("_id username userId phone email");

    if (!user)
      return res.status(404).json({ error: `No user found with User ID or phone "${query}". Please check and try again.` });

    const reservations = await Reservation.find({
      $or: [
        { reserverId:    user._id },
        { reserverEmail: user.email },
        ...(user.phone ? [{ reserverPhone: user.phone }] : []),
      ],
      collected:     false,
      codeExpiresAt: { $gt: new Date() },
    })
      .populate("foodItem", "foodItem foodQuantity location")
      .sort({ createdAt: -1 })
      .limit(10);

    if (!reservations.length)
      return res.status(404).json({ error: "No active reservations found for this user. Codes may have expired or all pickups are complete." });

    const shaped = reservations.map(r => ({
      _id:           r._id,
      reserverName:  r.reserverName,
      code:          r.code,
      codeExpiresAt: r.codeExpiresAt,
      foodItem:      r.foodItem?.foodItem || "Unknown Item",
      foodQuantity:  r.foodItem?.foodQuantity,
      location:      r.foodItem?.location,
      foodItemId:    r.foodItem?._id,
    }));

    res.json({
      name:         user.username || user.userId,
      userId:       user.userId,
      phone:        user.phone,
      reservations: shaped,
    });
  } catch (err) {
    console.error("search-by-user error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

/* ─────────────────────────────────────────────────────────────
   POST /api/reservations/resend-code-by-id
   After collector selects their specific reservation,
   send the donor a notification with the pickup code.

   Body: { reservationId: "..." }
─────────────────────────────────────────────────────────────── */
app.post("/api/reservations/resend-code-by-id", verifyToken, async (req, res) => {
  try {
    const { reservationId } = req.body;
    if (!reservationId)
      return res.status(400).json({ error: "reservationId is required." });

    const reservation = await Reservation.findById(reservationId)
      .populate({
        path: "foodItem",
        populate: { path: "user", select: "username _id" },
      });

    if (!reservation)
      return res.status(404).json({ error: "Reservation not found." });

    if (reservation.collected)
      return res.status(400).json({ error: "This item has already been collected." });

    if (reservation.codeExpiresAt < new Date())
      return res.status(410).json({ error: "This pickup code has expired (24h limit). Please make a new reservation." });

    const food  = reservation.foodItem;
    const donor = food?.user;

    if (!donor)
      return res.status(404).json({ error: "Could not find the donor for this reservation." });

    await Notification.create({
      recipient: donor._id,
      title:     "📦 Code Resend Request",
      message:   `${reservation.reserverName} forgot their pickup code for "${food?.foodItem || "your item"}". Their code is below — tap to copy and read it to them.`,
      code:      reservation.code,
      type:      "code_resend",
      read:      false,
    });

    console.log(`✅ resend-code-by-id: notification sent to donor ${donor.username} for reservation ${reservationId}`);

    res.json({
      message:   `✓ Notification sent to ${donor.username || "the donor"}! They will see the code in their notification bell.`,
      donorName: donor.username,
      foodItem:  food?.foodItem,
    });
  } catch (err) {
    console.error("resend-code-by-id error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
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