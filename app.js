require("dotenv").config();
const express = require("express");
const multer = require("multer");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const loginCheckerMiddleware = require("./login_checker_middleware");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const upload = multer();

var port = process.env.PORT || 3000;
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_NAME = process.env.DB_NAME;
const JWT_SECRET = process.env.JWT_SECRET;

const dbConnection = mysql.createConnection({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
});

// Connect to the database
dbConnection.connect((err) => {
  if (err) throw err;
  console.log("✅ Connected to MySQL");
});

/// user registration

app.post("/auth/register", upload.none(), async (req, res) => {
  const { name, phone, email, password } = req.body;

  const missingFields = [];
  if (!name) missingFields.push("name");
  if (!phone) missingFields.push("phone");
  if (!email) missingFields.push("email");
  if (!password) missingFields.push("password");

  if (missingFields.length > 0) {
    return res.status(400).json({
      message: `Missing required field(s): ${missingFields.join(", ")}`,
    });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store the user in the db
  dbConnection.query(
    "INSERT INTO users (name, phone, email, password) VALUES (?, ?, ?, ?)",
    [name, phone, email, hashedPassword],
    (error, results) => {
      if (error) {
        return res.status(500).json({ error: "Error registering user" });
      }
      var response = {
        userInfo: {
          id: results.insertId,
          name: name,
          phone: phone,
          email: email,
          password: hashedPassword,
        },
      };
      res
        .status(201)
        .json({ message: "User registered successfully", data: response });
    }
  );
});

/// user login

app.post("/auth/login", upload.none(), async (req, res) => {
  const { email, password } = req.body;
  // Check if the user exists
  dbConnection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (error, results) => {
      if (error) {
        return res.status(500).json({ error: "Error logging in" });
      }
      if (results.length === 0) {
        return res.status(401).json({ error: "Email not registered" });
      }

      const user = results[0];
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (isValidPassword) {
        // Generate a JWT token
        const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, {
          expiresIn: "1h",
        });
        var response = {
          userInfo: {
            id: user.id,
            name: user.name,
            phone: user.phone,
            email: user.email,
          },
          token: token,
        };

        res.json({ message: "Login successful", response });
      } else {
        return res.status(401).json({ error: "Invalid credentials" });
      }
    }
  );
});

app.get("/auth/user", loginCheckerMiddleware, (req, res) => {
  // Get the user ID from the request object
  const id = req.id;
  console.log(`user id is: ${id}`);

  // Fetch the user from the database
  dbConnection.query(
    "SELECT id, name, phone, email FROM users WHERE id = ?",
    [id],
    (error, results) => {
      if (error) {
        return res.status(500).json({ error: "Error fetching user" });
      }
      if (results.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }
      const user = results[0];
      res.json({ message: "User fetched successfully", user });
    }
  );
});

app.get("/auth/all-users", loginCheckerMiddleware, (req, res) => {
  // Fetch all users from the database
  dbConnection.query(
    "SELECT id, name, phone, email FROM users",
    (error, results) => {
      if (error) {
        return res.status(500).json({ error: "Error fetching users" });
      }
      res.json({ message: "Users fetched successfully", users: results });
    }
  );
});

/// server start
app.listen(port, function () {
  console.log(`Server is running on port on ${port}`);
});
