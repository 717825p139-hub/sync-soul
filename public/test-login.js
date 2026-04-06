const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");

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

mongoose.connect("mongodb://localhost:27017/syncsoul").then(async () => {
  const user = await User.findOne({ username: "admin" });
  console.log("Found user:", user ? user.username : "NOT FOUND");
  console.log("Password in DB:", user.password);
  console.log("Password length:", user.password.length);
  
  const match = await bcrypt.compare("admin123", user.password);
  console.log("Password match:", match);
  console.log("isAdmin:", user.isAdmin);
  process.exit();
}).catch(err => { console.error(err); process.exit(1); });