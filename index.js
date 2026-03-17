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

const recipeRoutes = require("./routes/recipes");

const app = express();
const port = process.env.PORT || 5000;

/* ===========================
   STARTUP ENV CHECK
=========================== */
const requiredEnvVars = ["MONGODB_URI", "JWT_SECRET"];
const missingVars = requiredEnvVars.filter((v) => !process.env[v]);
if (missingVars.length > 0) {
  console.error(`❌ Missing required environment variables: ${missingVars.join(", ")}`);
  console.error("   Set these in Render → Environment before deploying.");
  process.exit(1);
}

/* ===========================
   MIDDLEWARE
=========================== */

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  process.env.FRONTEND_URL,
].filter(Boolean); // removes undefined if FRONTEND_URL is not set

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (Postman, mobile apps, curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Handle preflight OPTIONS requests for all routes
app.options("*", cors());

app.use(express.json());

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Register recipe routes AFTER middleware
app.use("/api/recipes", recipeRoutes);


/* ===========================
   DATABASE CONNECTION
=========================== */

const mongoURI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/feedforward";
mongoose
  .connect(mongoURI)
  .then(() => console.log("✅ FeedForward DB connected"))
  .catch((err) => {
    console.error("❌ DB connection error:", err);
    process.exit(1);
  });


/* ===========================
   JWT
=========================== */

const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key";

// JWT Middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized - No token" });
  }
  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.userId = decoded.userId;
    next();
  });
};


/* ===========================
   SCHEMAS & MODELS
=========================== */

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  resetToken: { type: String, default: null }, // FIX #4: track reset tokens
});
const User = mongoose.model("User", userSchema);

const wasteSchema = new mongoose.Schema({
  user:          { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  foodItem:      { type: String, required: true, trim: true },
  foodQuantity:  { type: Number, required: true },
  foodReason:    { type: String, required: true, trim: true },
  foodWasteDate: { type: Date, default: Date.now },
  location:      { type: String, required: true, trim: true },
  image:         { type: String, default: null },
  approved:      { type: Boolean, default: false },
});
const WasteData = mongoose.model("WasteData", wasteSchema);

const inventorySchema = new mongoose.Schema({
  user:             { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  itemName:         { type: String, required: true, trim: true },
  itemQuantity:     { type: Number, required: true },
  itemCost:         { type: Number, required: true },
  itemPurchaseDate: { type: Date, required: true },
  itemExpiryDate:   { type: Date, required: true },
  consumed:         { type: Boolean, default: false },
});
const Inventory = mongoose.model("Inventory", inventorySchema);


/* ===========================
   MULTER FILE UPLOAD
   FIX #6: Added 5MB file size limit
=========================== */

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = "./uploads";
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|webp/;
    const isValid = allowedTypes.test(path.extname(file.originalname).toLowerCase())
                 && allowedTypes.test(file.mimetype);
    if (isValid) {
      cb(null, true);
    } else {
      cb(new Error("Only image files (jpeg, jpg, png, webp) are allowed"));
    }
  },
});


/* ===========================
   EMAIL HELPER
=========================== */

const sendPasswordResetEmail = async (email, resetToken) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: "Password Reset Request",
    html: `<p>You requested a password reset. Click below:</p><a href="${resetUrl}">Reset Password</a><p>This link expires in 1 hour.</p>`,
  };

  await transporter.sendMail(mailOptions);
};


/* ===========================
   AUTH ROUTES
   FIX #1: Prefixed all routes with /api
=========================== */

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // FIX #5: Basic input validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username: username.trim(), email: email.toLowerCase().trim(), password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    res.status(500).json({ error: "Registration failed." });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed." });
  }
});

// Forgot Password
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(404).json({ error: "User not found" });

    // FIX #4: Store token on user so it can be invalidated after use
    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
    user.resetToken = resetToken;
    await user.save();

    await sendPasswordResetEmail(email, resetToken);
    res.json({ message: "Reset link sent to your email" });
  } catch (err) {
    res.status(500).json({ error: "Failed to send reset email" });
  }
});

// Reset Password
app.post("/api/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // FIX #4: Reject if token doesn't match (already used or replaced)
    if (user.resetToken !== token) {
      return res.status(400).json({ error: "Reset link has already been used or expired" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetToken = null; // Invalidate token after use
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ error: "Reset failed" });
  }
});


/* ===========================
   WASTE ROUTES
   FIX #1: Prefixed with /api
   FIX #2: Ownership checks on delete/patch
   FIX #3: Approve route placed BEFORE /:id route
=========================== */

// Create waste entry
app.post("/api/waste", verifyToken, upload.single("image"), async (req, res) => {
  try {
    const { foodItem, foodQuantity, foodReason, foodWasteDate, location } = req.body;
    const imagePath = req.file ? req.file.filename : null;

    if (!foodItem || !foodQuantity || !foodReason || !foodWasteDate || !location) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const newWaste = new WasteData({
      user: req.userId,
      foodItem,
      foodQuantity,
      foodReason,
      foodWasteDate,
      location,
      image: imagePath,
    });
    await newWaste.save();
    res.status(201).json({ message: "Waste data recorded", data: newWaste });
  } catch (err) {
    res.status(500).json({ error: "Failed to save waste data" });
  }
});

// Get all waste entries for current user
app.get("/api/waste", verifyToken, async (req, res) => {
  try {
    const wasteData = await WasteData.find({ user: req.userId });
    res.json(wasteData);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch waste data" });
  }
});

// FIX #3: Approve route BEFORE /:id to avoid route conflict
app.patch("/api/waste/approve/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // FIX #2: Ownership check
    const wasteItem = await WasteData.findOne({ _id: id, user: req.userId });
    if (!wasteItem) return res.status(404).json({ error: "Waste item not found" });
    if (wasteItem.approved) return res.status(400).json({ error: "Already approved" });

    wasteItem.approved = true;
    wasteItem.foodQuantity -= 10;
    await wasteItem.save();
    res.json({ message: "Food item approved", data: wasteItem });
  } catch (err) {
    res.status(500).json({ error: "Approval failed" });
  }
});

// Delete waste entry
app.delete("/api/waste/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // FIX #2: Ownership check — only delete if it belongs to this user
    const deletedWaste = await WasteData.findOneAndDelete({ _id: id, user: req.userId });
    if (!deletedWaste) return res.status(404).json({ error: "Waste item not found" });

    res.json({ message: `Waste item "${deletedWaste.foodItem}" deleted successfully!` });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete waste item" });
  }
});


/* ===========================
   INVENTORY ROUTES
   FIX #1: Prefixed with /api
   FIX #2: Ownership checks on delete/patch
   FIX #3: Approve route placed BEFORE /:id route
=========================== */

// Create inventory item
app.post("/api/inventory", verifyToken, async (req, res) => {
  try {
    const { itemName, itemQuantity, itemCost, itemPurchaseDate, itemExpiryDate } = req.body;

    if (!itemName || !itemQuantity || !itemCost || !itemPurchaseDate || !itemExpiryDate) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const newItem = new Inventory({
      user: req.userId,
      itemName,
      itemQuantity,
      itemCost,
      itemPurchaseDate,
      itemExpiryDate,
      consumed: false,
    });
    await newItem.save();
    res.status(201).json({ message: "Inventory item added", data: newItem });
  } catch (err) {
    res.status(500).json({ error: "Failed to add inventory item" });
  }
});

// Get all inventory items for current user
app.get("/api/inventory", verifyToken, async (req, res) => {
  try {
    const inventoryItems = await Inventory.find({ user: req.userId });
    res.json(inventoryItems);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch inventory items" });
  }
});

// FIX #3: Approve route BEFORE /:id to avoid route conflict
app.patch("/api/inventory/approve/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // FIX #2: Ownership check
    const inventoryItem = await Inventory.findOne({ _id: id, user: req.userId });
    if (!inventoryItem) return res.status(404).json({ error: "Inventory item not found" });
    if (inventoryItem.consumed) return res.status(400).json({ error: "Already consumed" });

    inventoryItem.consumed = true;
    await inventoryItem.save();
    res.json({ message: "Inventory item consumed", data: inventoryItem });
  } catch (err) {
    res.status(500).json({ error: "Failed to approve inventory item" });
  }
});

// Update inventory item quantity
app.patch("/api/inventory/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { itemQuantity } = req.body;

    if (!itemQuantity) return res.status(400).json({ error: "Item quantity is required" });

    // FIX #2: Ownership check
    const inventoryItem = await Inventory.findOne({ _id: id, user: req.userId });
    if (!inventoryItem) return res.status(404).json({ error: "Inventory item not found" });

    inventoryItem.itemQuantity = itemQuantity;
    await inventoryItem.save();
    res.json({ message: "Inventory item updated", data: inventoryItem });
  } catch (err) {
    res.status(500).json({ error: "Failed to update inventory item" });
  }
});

// Delete inventory item
app.delete("/api/inventory/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // FIX #2: Ownership check — only delete if it belongs to this user
    const deletedInventory = await Inventory.findOneAndDelete({ _id: id, user: req.userId });
    if (!deletedInventory) return res.status(404).json({ error: "Inventory item not found" });

    res.json({ message: `Inventory item "${deletedInventory.itemName}" deleted successfully!` });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete inventory item" });
  }
});


/* ===========================
   GLOBAL ERROR HANDLER
   (handles multer errors etc.)
=========================== */

app.use((err, req, res, next) => {
  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({ error: "File too large. Maximum size is 5MB." });
  }
  if (err.message && err.message.includes("Only image files")) {
    return res.status(400).json({ error: err.message });
  }
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});


/* ===========================
   START SERVER
=========================== */

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});