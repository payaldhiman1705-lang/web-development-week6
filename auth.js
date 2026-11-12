const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const auth = require("../middleware/auth");

const router = express.Router();

// SIGNUP
router.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: "Sab fields bharo" });
    }
    if (!email.includes("@")) {
      return res.status(400).json({ message: "Valid email daalo" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password kam se kam 6 characters ka ho" });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ message: "Email pehle se registered hai" });
    }

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ firstName, lastName, email, password: hashed });

    res.status(201).json({ message: "Signup successful!" });
  } catch (err) {
    console.log("SIGNUP ERROR:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email aur password daalo" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ message: "Email ya password galat hai" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: "Email ya password galat hai" });
    }

    const token = jwt.sign(
      { id: user._id, firstName: user.firstName },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ message: "Login successful!", token, firstName: user.firstName });
  } catch (err) {
    console.log("LOGIN ERROR:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// ME
router.get("/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("firstName lastName email");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    console.log("ME ERROR:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;