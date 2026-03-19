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
   ENV CHECK
=========================== */
const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";
const MONGO_URI  = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/feedforward";

/* ===========================
   CORS — FIRST (before everything)
=========================== */
const allowedOrigins = [
  process.env.FRONTEND_URL,
  "http://localhost:3000",
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.log("❌ CORS Blocked:", origin);
    callback(new Error("CORS blocked"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.options("*", cors(corsOptions));
app.use(cors(corsOptions));

/* ===========================
   SECURITY
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

app.use("/uploads",     express.static(path.join(__dirname, "uploads")));
app.use("/api/uploads", express.static(path.join(__dirname, "uploads")));

app.use("/api/recipes", recipeRoutes);

/* ===========================
   DATABASE
=========================== */
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Connected"))
.catch((err) => {
  console.error("❌ DB Error:", err.message);
  process.exit(1);
});

/* ===========================
   HELPER — generate short human-readable user ID
   Format: FF-XXXXXX  (FF = FeedForward prefix, 6 alphanumeric chars)
   e.g.  FF-A3K9PZ
=========================== */
const generateUserId = () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I to avoid confusion
  let id = "FF-";
  for (let i = 0; i < 6; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
};

/* ===========================
   MODELS
=========================== */
const UserSchema = new mongoose.Schema({
  userId:     { type: String, unique: true },          // ← NEW: readable unique ID e.g. FF-A3K9PZ
  username:   { type: String, required: true },
  email:      { type: String, unique: true, required: true },
  phone:      { type: String, default: "" },
  gender:     {                                         // ← NEW: stored from signup form
    type: String,
    enum: ["male", "female", "other", "prefer_not", ""],
    default: "",
  },
  password:   { type: String, required: true },
  resetToken: { type: String, default: null },
}, { timestamps: true }); // createdAt + updatedAt

// Auto-generate userId before saving if not already set
UserSchema.pre("save", async function (next) {
  if (this.userId) return next();
  let uid, exists;
  do {
    uid = generateUserId();
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

/* ===========================
   MULTER + CLOUDINARY
=========================== */
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
      user: process.env.EMAIL_USER || process.env.EMAIL,
      pass: process.env.EMAIL_PASS || process.env.EMAIL_PASSWORD,
    },
  });

  const url = `${process.env.FRONTEND_URL}/reset-password/${token}`;
  await transporter.sendMail({
    from: process.env.EMAIL_USER || process.env.EMAIL,
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
          If you didn't request this, you can safely ignore this email.
        </p>
      </div>
    `,
  });
};

/* ===========================
   HEALTH ROUTES
=========================== */
app.get("/", (req, res) => res.send("🚀 FeedForward API Running"));

app.get("/api/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

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

// Register — now also saves gender
const handleRegister = async (req, res) => {
  try {
    const { username, email, password, phone, gender } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    if (password.length < 6)
      return res.status(400).json({ error: "Password too short (min 6 chars)" });

    if (await User.findOne({ email }))
      return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hash,
      phone:  phone  || "",
      gender: gender || "",
      // userId is auto-generated by the pre-save hook
    });
    await newUser.save();

    res.status(201).json({
      message: "Registered successfully",
      userId:  newUser.userId, // return it so frontend can show it immediately if needed
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
};
app.post("/register",     handleRegister);
app.post("/api/register", handleRegister);

// Login
const handleLogin = async (req, res) => {
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

/* ===========================
   PROFILE ROUTES
   GET  /api/profile  — return full user info (no password / resetToken)
   PUT  /api/profile  — update username, phone, gender
=========================== */

app.get("/api/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password -resetToken");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

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

/* ===========================
   WASTE ROUTES
=========================== */

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
    res.status(201).json(waste);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save waste entry" });
  }
};
app.post("/waste",     verifyToken, upload.single("image"), handleCreateWaste);
app.post("/api/waste", verifyToken, upload.single("image"), handleCreateWaste);

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

/* ===========================
   INVENTORY ROUTES
=========================== */

const handleCreateInventory = async (req, res) => {
  try {
    const { itemName, itemQuantity, itemCost, itemPurchaseDate, itemExpiryDate } = req.body;

    if (!itemName || !itemQuantity || !itemCost || !itemPurchaseDate || !itemExpiryDate)
      return res.status(400).json({ error: "All fields are required" });

    const item = new Inventory({
      user: req.userId,
      itemName, itemQuantity, itemCost, itemPurchaseDate, itemExpiryDate,
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

const handleGetInventory = async (req, res) => {
  try {
    res.json(await Inventory.find({ user: req.userId }));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch inventory" });
  }
};
app.get("/inventory",     verifyToken, handleGetInventory);
app.get("/api/inventory", verifyToken, handleGetInventory);

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
   START
=========================== */
app.listen(port, () => {
  console.log(`🚀 FeedForward API running on port ${port}`);
});