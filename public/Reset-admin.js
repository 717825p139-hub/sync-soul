const mongoose = require("mongoose");
const bcrypt   = require("bcryptjs");

mongoose.connect("mongodb://localhost:27017/syncsoul").then(async () => {
  const db   = mongoose.connection.collection("users");
  const deleted = await db.deleteMany({ username: "admin" });
  console.log("Deleted admin accounts:", deleted.deletedCount);
  const hash = await bcrypt.hash("admin123", 10);
  console.log("New hash:", hash);
  const verify = await bcrypt.compare("admin123", hash);
  console.log("Hash verification:", verify);
  
  await db.insertOne({
    username  : "admin",
    password  : hash,
    email     : "admin@syncsoul.com",
    phone     : "0000000000",
    isAdmin   : true,
    createdAt : new Date()
  });
  
  console.log("Admin created! Login: admin / admin123");
  process.exit();
}).catch(err => { console.error(err); process.exit(1); });