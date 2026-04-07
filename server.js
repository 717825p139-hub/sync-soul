require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

/* ================= MIDDLEWARE ================= */
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));
app.use(express.static(path.join(__dirname, "public")));

/* ================= DATABASE CONNECTION ================= */

// 🔥 IMPORTANT: Remove localhost fallback in production
const MONGO_URI = process.env.MONGODB_URI;

if (!MONGO_URI) {
  console.error("❌ MONGODB_URI is NOT set in environment variables");
  process.exit(1);
}

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ Connected to MongoDB"))
.catch(err => {
  console.error("❌ MongoDB connection error FULL:", err);
  process.exit(1);
});

/* ================= SCHEMA ================= */

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, required: true },
  gender: { type: String, default: "" },
  dob: { type: String, default: "" },
  cast: { type: String, default: "" },
  salary: { type: String, default: "" },
  fname: { type: String, default: "" },
  mname: { type: String, default: "" },
  bio: { type: String, default: "" },
  photo: { type: String, default: "" },
  isAdmin: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ================= OTP STORE ================= */
const otpStore = new Map();

/* ================= EMAIL CONFIG ================= */

const transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 587,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendOTPEmail(toEmail, otp) {
  await transporter.sendMail({
    from: '"SYNC SOUL" <a68bdd001@smtp-brevo.com>',
    to: toEmail,
    subject: "Your SYNC SOUL OTP Code",
    html: `
      <div style='font-family:Arial;max-width:400px;margin:auto;padding:30px;background:#1a0010;border-radius:15px;color:white;'>
        <h2 style='color:hotpink;text-align:center;'>SYNC SOUL</h2>
        <p style='text-align:center;font-size:16px;'>Your One-Time Password:</p>
        <div style='background:#e63973;color:white;font-size:36px;font-weight:bold;text-align:center;padding:20px;border-radius:10px;letter-spacing:8px;'>${otp}</div>
        <p style='text-align:center;color:#aaa;margin-top:15px;'>Expires in 5 minutes.</p>
      </div>
    `,
  });
}

function isExpired(expires) {
  return Date.now() > expires;
}

/* ================= ROUTES ================= */

app.get("/", (req, res) => {
  res.send("SYNC SOUL Backend is Running 🚀");
});

/* ===== REGISTER ===== */

app.post("/api/register", async (req, res) => {
  try {
    const { username, password, email, phone, gender, dob, cast, salary, fname, mname, bio, photo } = req.body;

    if (!username || !password || !email || !phone)
      return res.status(400).json({ error: "Required fields missing" });

    if (password.length < 6)
      return res.status(400).json({ error: "Password too short" });

    const existing = await User.findOne({
      $or: [
        { username: new RegExp("^" + username + "$", "i") },
        { email: email.toLowerCase() }
      ]
    });

    if (existing)
      return res.status(409).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    otpStore.set(email.toLowerCase(), {
      otp,
      expires: Date.now() + 5 * 60 * 1000,
      pendingUser: {
        username,
        password: hashedPassword,
        email: email.toLowerCase(),
        phone,
        gender,
        dob,
        cast,
        salary,
        fname,
        mname,
        bio,
        photo: photo || ""
      }
    });

    await sendOTPEmail(email, otp);

    res.json({ message: "OTP sent" });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ===== VERIFY OTP ===== */

app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const entry = otpStore.get(email.toLowerCase());

    if (!entry) return res.status(400).json({ error: "No OTP found" });

    if (isExpired(entry.expires)) {
      otpStore.delete(email.toLowerCase());
      return res.status(400).json({ error: "OTP expired" });
    }

    if (entry.otp !== otp)
      return res.status(400).json({ error: "Invalid OTP" });

    const user = new User(entry.pendingUser);
    await user.save();

    otpStore.delete(email.toLowerCase());

    res.json({ message: "Registration successful" });

  } catch (err) {
    console.error("VERIFY ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===== LOGIN ===== */

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({
      username: new RegExp("^" + username + "$", "i")
    });

    if (!user) return res.status(401).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(401).json({ error: "Wrong password" });

    res.json({
      message: "Login successful",
      username: user.username,
      isAdmin: user.isAdmin
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===== START SERVER ===== */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
