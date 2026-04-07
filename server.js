require("dotenv").config();
const express    = require("express");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const cors       = require("cors");
const nodemailer = require("nodemailer");
const path       = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));
app.use(express.static(path.join(__dirname, "public")));

mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/syncsoul")
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => { console.error("MongoDB connection error:", err); process.exit(1); });

const userSchema = new mongoose.Schema({
  username : { type: String, required: true, unique: true, trim: true },
  password : { type: String, required: true },
  email    : { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone    : { type: String, required: true },
  gender   : { type: String, default: "" },
  dob      : { type: String, default: "" },
  cast     : { type: String, default: "" },
  salary   : { type: String, default: "" },
  fname    : { type: String, default: "" },
  mname    : { type: String, default: "" },
  bio      : { type: String, default: "" },
  photo    : { type: String, default: "" },
  isAdmin  : { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const otpStore = new Map();

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
    from    : '"SYNC SOUL" <sirpranav08@gmail.com>',
    to      : toEmail,
    subject : "Your SYNC SOUL OTP Code",
    html    : "<div style='font-family:Arial;max-width:400px;margin:auto;padding:30px;background:#1a0010;border-radius:15px;color:white;'><h2 style='color:hotpink;text-align:center;'>SYNC SOUL</h2><p style='text-align:center;font-size:16px;'>Your One-Time Password:</p><div style='background:#e63973;color:white;font-size:36px;font-weight:bold;text-align:center;padding:20px;border-radius:10px;letter-spacing:8px;'>" + otp + "</div><p style='text-align:center;color:#aaa;margin-top:15px;'>Expires in 5 minutes. Do not share this code.</p></div>",
  });
}

function isExpired(expires) {
  return Date.now() > expires;
}

app.post("/api/register", async (req, res) => {
  try {
    const { username, password, email, phone, gender, dob, cast, salary, fname, mname, bio, photo } = req.body;
    if (!username || !password || !email || !phone) {
      return res.status(400).json({ error: "Username, password, email and phone are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email address." });
    }
    const digits = phone.replace(/\D/g, "");
    if (digits.length < 10) {
      return res.status(400).json({ error: "Phone must be at least 10 digits." });
    }
    const existing = await User.findOne({
      $or: [
        { username: { $regex: new RegExp("^" + username + "$", "i") } },
        { email: email.toLowerCase() }
      ]
    });
    if (existing) {
      if (existing.username.toLowerCase() === username.toLowerCase()) {
        return res.status(409).json({ error: "Username already taken." });
      }
      return res.status(409).json({ error: "Email already registered." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email.toLowerCase(), {
      otp,
      expires     : Date.now() + 5 * 60 * 1000,
      pendingUser : { username, password: hashedPassword, email: email.toLowerCase(), phone, gender, dob, cast, salary, fname, mname, bio, photo: photo || "" }
    });
    await sendOTPEmail(email, otp);
    res.json({ message: "OTP sent to your email." });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const entry = otpStore.get(email.toLowerCase());
    if (!entry)                   return res.status(400).json({ error: "No OTP found. Please register again." });
    if (isExpired(entry.expires)) { otpStore.delete(email.toLowerCase()); return res.status(400).json({ error: "OTP expired. Please register again." }); }
    if (entry.otp !== otp)        return res.status(400).json({ error: "Invalid OTP." });
    const user = new User(entry.pendingUser);
    try {
      await user.save();
    } catch (saveErr) {
      if (saveErr.name === "MongoServerError" || saveErr.message.includes("BSONObj")) {
        entry.pendingUser.photo = "";
        const userNoPhoto = new User(entry.pendingUser);
        await userNoPhoto.save();
      } else { throw saveErr; }
    }
    otpStore.delete(email.toLowerCase());
    res.json({ message: "Registration successful!" });
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required." });
    const user = await User.findOne({ username: { $regex: new RegExp("^" + username + "$", "i") } });
    if (!user) return res.status(401).json({ error: "User not found." });
    const match = await bcrypt.compare(password, user.password);
    console.log("Login attempt:", username, "match:", match, "isAdmin:", user.isAdmin);
    if (!match) return res.status(401).json({ error: "Invalid password." });
    res.json({ message: "Login successful.", username: user.username, isAdmin: user.isAdmin || false });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { username, email } = req.body;
    if (!username || !email) return res.status(400).json({ error: "Username and email required." });
    const user = await User.findOne({ username: { $regex: new RegExp("^" + username + "$", "i") } });
    if (!user)                              return res.status(404).json({ error: "User not found." });
    if (user.email !== email.toLowerCase()) return res.status(400).json({ error: "Email does not match." });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set("reset_" + email.toLowerCase(), {
      otp,
      expires  : Date.now() + 5 * 60 * 1000,
      username : user.username
    });
    await sendOTPEmail(email, otp);
    res.json({ message: "OTP sent to your email." });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const key   = "reset_" + email.toLowerCase();
    const entry = otpStore.get(key);
    if (!entry)                   return res.status(400).json({ error: "No reset request found. Please start again." });
    if (isExpired(entry.expires)) { otpStore.delete(key); return res.status(400).json({ error: "OTP expired." }); }
    if (entry.otp !== otp)        return res.status(400).json({ error: "Invalid OTP." });
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });
    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ username: entry.username }, { password: hashed });
    otpStore.delete(key);
    res.json({ message: "Password reset successful." });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.get("/api/profiles", async (req, res) => {
  try {
    const users = await User.find({ isAdmin: { $ne: true } }, "-password -__v -photo").lean();
    res.json(users);
  } catch (err) {
    console.error("Profiles error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

app.get("/api/photo/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id, "photo").lean();
    if (!user) return res.status(404).json({ error: "Not found." });
    res.json({ photo: user.photo || "" });
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

function requireAdmin(req, res, next) {
  const adminUser = req.headers["x-admin-user"];
  if (!adminUser) return res.status(403).json({ error: "Forbidden." });
  User.findOne({ username: adminUser, isAdmin: true }).then(function(u) {
    if (!u) return res.status(403).json({ error: "Forbidden." });
    next();
  }).catch(function() { res.status(500).json({ error: "Server error." }); });
}

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({ isAdmin: { $ne: true } }, "-password -__v -photo").lean();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

app.delete("/api/admin/delete/:id", requireAdmin, async (req, res) => {
  try {
    const deleted = await User.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "User not found." });
    res.json({ message: "User deleted successfully." });
  } catch (err) {
    res.status(500).json({ error: "Server error." });
  }
});

app.listen(PORT, () => {
  console.log("SYNC SOUL server running at http://localhost:" + PORT);
});
