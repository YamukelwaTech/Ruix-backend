const express = require("express"); // Importing Express.js framework
const argon2 = require("argon2"); // Password hashing library
const jwt = require("jsonwebtoken"); // JSON Web Token library
const { OAuth2Client } = require("google-auth-library"); // Google OAuth2 client
const pool = require("./db"); // Database connection pool
const cors = require("cors"); // Cross-Origin Resource Sharing middleware

const app = express(); // Creating Express application
const port = process.env.PORT || 5000; // Setting server port

app.use(cors()); // Enabling CORS for all routes
app.use(express.json()); // Parsing JSON requests

// Middleware to set cross-origin policies
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  next();
});

const jwtSecret = process.env.JWT_SECRET; // JWT secret key
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET); // Creating Google OAuth2 client

// Handling Google login endpoint
app.post("/api/google-login", async (req, res) => {
  const { code } = req.body; // Authorization code from Google

  try {
    // Exchanging code for tokens
    const { tokens } = await client.getToken({
      code,
      redirect_uri: process.env.REDIRECT_URI,
    });

    const idToken = tokens.id_token; // Extracting ID token

    // Verifying ID token with Google
    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload(); // Extracting user payload
    const email = payload.email; // User email
    const name = payload.name; // User name

    // Checking if user exists in database, inserting if not
    const [user] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);

    let newUser;
    if (user.length === 0) {
      const [result] = await pool.query("INSERT INTO users (name, email) VALUES (?, ?)", [name, email]);
      newUser = { id: result.insertId, name, email };
    } else {
      newUser = user[0];
    }

    // Creating JWT token for user
    const token = jwt.sign({ id: newUser.id, email: newUser.email }, jwtSecret, {
      expiresIn: "1h",
    });

    res.json({ token }); // Sending token in response
  } catch (error) {
    console.error("Google login error:", error);
    res.status(500).json({ message: "Google login failed!", error: error.message });
  }
});

// Handling user registration endpoint
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body; // User details

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Regex for email validation

  // Validating email format and password criteria
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format." });
  }

  if (password.length < 6 || !/\d/.test(password)) {
    return res.status(400).json({
      message: "Password must be at least 6 characters long and contain at least one number.",
    });
  }

  try {
    // Checking if email already exists in database
    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (users.length > 0) {
      return res.status(400).json({ message: "Email already exists." });
    }

    // Hashing password using Argon2
    const hashedPassword = await argon2.hash(password);

    // Inserting new user into database
    const [result] = await pool.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);

    // Creating JWT token for new user
    const token = jwt.sign({ id: result.insertId, email }, jwtSecret, { expiresIn: "1h" });

    res.status(201).json({ message: "User registered successfully", token }); // Sending success response with token
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

// Endpoint to fetch all users
app.get("/api/users", async (req, res) => {
  try {
    // Fetching all users from database
    const [users] = await pool.query("SELECT id, name, email FROM users");

    res.status(200).json(users); // Sending users data as response
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

// Endpoint to delete a user
app.delete("/api/users", async (req, res) => {
  const { email } = req.body; // User email to delete

  try {
    // Deleting user from database
    const [result] = await pool.query("DELETE FROM users WHERE email = ?", [email]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({ message: "User deleted successfully." }); // Sending success message
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

// Starting the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
