const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const EmployeeModel = require("./modal/user");
const auth = require("./middleware/auth");
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect("mongodb://127.0.0.1:27017/flareMind");
const JWT_SECRET = "your_secret_key";

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const exists = await EmployeeModel.findOne({ email });
    if (exists) return res.status(400).json({ error: "Email already registered" });
    const hashed = await bcrypt.hash(password, 10);
    const user = await EmployeeModel.create({
      name,
      email,
      password: hashed,
    });
    res.json({ id: user._id, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Register failed" });
  }
});


app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await EmployeeModel.findOne({ email });
    if (!user) return res.status(400).json({ error: "No record existed" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "The password is incorrect" });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});


app.get("/users", auth, async (req, res) => {
  try {
    const users = await EmployeeModel.find({ _id: { $ne: req.user.id } })
      .select("_id name email");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/users/:id", auth, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const update = { name, email };

    if (password) {
      update.password = await bcrypt.hash(password, 10);
    }

    const user = await EmployeeModel.findByIdAndUpdate(
      req.params.id,
      update,
      { new: true, runValidators: true }
    ).select("_id name email");

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Update failed" });
  }
});

app.listen(3001, () => console.log("✅ API running on http://localhost:3001"));
