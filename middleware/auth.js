const jwt = require("jsonwebtoken");
module.exports = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Access denied, no token" });
const JWT_SECRET = "your_secret_key";
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified; // { id, email }
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

