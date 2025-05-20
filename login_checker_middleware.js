require("dotenv").config();
const jwt = require("jsonwebtoken");

const loginCheckerMiddleware = (req, res, next) => {
  try {
    if (!req.headers.authorization) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const token = req.headers.authorization.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Unauthorized" });
      }
      const { id, name } = decoded;
      req.id = id;
      req.name = name;
      next();
    });
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Authentication failed: " + error.message });
  }
};

module.exports = loginCheckerMiddleware;
