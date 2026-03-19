require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"); // ✅ FIX ADDED
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const recipeRoutes = require("./routes/recipes");

const app = express();
const port = process.env.PORT || 5000;

/* ===========================
   MIDDLEWARE
=========================== */

app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true,
}));

app.use(express.json());

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ✅ Register recipe route AFTER middleware
app.use("/api/recipes", recipeRoutes);


// MongoDB Connection
const mongoURI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/feedforward";
mongoose
  .connect(mongoURI)
  .then(() => console.log("✅ FeedForward DB connected"))
  .catch((err) => {
    console.error("❌ DB connection error:", err);
    process.exit(1);
  });

// JWT Secret
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

// Schemas & Models
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

const wasteSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  foodItem: String,
  foodQuantity: Number,
  foodReason: String,
  foodWasteDate: { type: Date, default: Date.now },
  location: String,
  image: String,
  approved: { type: Boolean, default: false },
});
const WasteData = mongoose.model("WasteData", wasteSchema);

const inventorySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  itemName: String,
  itemQuantity: Number,
  itemCost: Number,
  itemPurchaseDate: Date,
  itemExpiryDate: Date,
  consumed: Boolean,
});
const Inventory = mongoose.model("Inventory", inventorySchema);

// Multer Image Upload
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
const upload = multer({ storage });

// Password Reset Email
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
    html: `<p>You requested a password reset. Click below:</p><a href="${resetUrl}">Reset Password</a>`,
  };

  await transporter.sendMail(mailOptions);
};

// Routes

// Register
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.json({ message: "User registered successfully!" });
  } catch (err) {
    res.status(500).json({ error: "Registration failed." });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
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
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
    await sendPasswordResetEmail(email, resetToken);
    res.json({ message: "Reset link sent to your email" });
  } catch (err) {
    res.status(500).json({ error: "Failed to send reset email" });
  }
});

// Reset Password
app.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();
    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ error: "Reset failed" });
  }
});

// Waste Routes
app.post("/waste", verifyToken, upload.single("image"), async (req, res) => {
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
    res.json({ message: "Waste data recorded", data: newWaste });
  } catch (err) {
    res.status(500).json({ error: "Failed to save waste data" });
  }
});

app.get("/waste", verifyToken, async (req, res) => {
  try {
    const wasteData = await WasteData.find({ user: req.userId });
    res.json(wasteData);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch waste data" });
  }
});

app.delete("/waste/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedWaste = await WasteData.findByIdAndDelete(id);
    if (!deletedWaste) return res.status(404).json({ error: "Waste item not found" });
    res.json({ message: `Waste item \"${deletedWaste.foodItem}\" deleted successfully!` });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete waste item" });
  }
});

app.patch("/waste/approve/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const wasteItem = await WasteData.findById(id);
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

// Inventory Routes
app.post("/inventory", verifyToken, async (req, res) => {
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
    res.json({ message: "Inventory item added", data: newItem });
  } catch (err) {
    res.status(500).json({ error: "Failed to add inventory item" });
  }
});

app.get("/inventory", verifyToken, async (req, res) => {
  try {
    const inventoryItems = await Inventory.find({ user: req.userId });
    res.json(inventoryItems);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch inventory items" });
  }
});

app.patch("/inventory/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { itemQuantity } = req.body;
    if (!itemQuantity) return res.status(400).json({ error: "Item quantity is required" });
    const inventoryItem = await Inventory.findById(id);
    if (!inventoryItem) return res.status(404).json({ error: "Inventory item not found" });
    inventoryItem.itemQuantity = itemQuantity;
    await inventoryItem.save();
    res.json({ message: "Inventory item updated", data: inventoryItem });
  } catch (err) {
    res.status(500).json({ error: "Failed to update inventory item" });
  }
});

app.delete("/inventory/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedInventory = await Inventory.findByIdAndDelete(id);
    if (!deletedInventory) return res.status(404).json({ error: "Inventory item not found" });
    res.json({ message: `Inventory item \"${deletedInventory.itemName}\" deleted successfully!` });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete inventory item" });
  }
});

app.patch("/inventory/approve/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const inventoryItem = await Inventory.findById(id);
    if (!inventoryItem) return res.status(404).json({ error: "Inventory item not found" });
    if (inventoryItem.consumed) return res.status(400).json({ error: "Already consumed" });
    inventoryItem.consumed = true;
    await inventoryItem.save();
    res.json({ message: "Inventory item consumed", data: inventoryItem });
  } catch (err) {
    res.status(500).json({ error: "Failed to approve inventory item" });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});