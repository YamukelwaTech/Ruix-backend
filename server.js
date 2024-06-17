const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const pool = require("./db");
const cors = require("cors");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors()); // Enabling CORS
app.use(express.json());
app.use(passport.initialize());

// JWT Secret
const jwtSecret = process.env.JWT_SECRET;

// Passport Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value;
      const name = profile.displayName;

      try {
        const [user] = await pool.query("SELECT * FROM users WHERE email = ?", [
          email,
        ]);

        if (user.length === 0) {
          const [result] = await pool.query(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            [name, email]
          );
          user = { id: result.insertId, name, email };
        } else {
          user = user[0];
        }

        const token = jwt.sign({ email: user.email }, jwtSecret, {
          expiresIn: "1h",
        });
        done(null, { token });
      } catch (error) {
        done(error, null);
      }
    }
  )
);

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format." });
  }

  if (password.length < 6 || !/\d/.test(password)) {
    return res.status(400).json({
      message:
        "Password must be at least 6 characters long and contain at least one number.",
    });
  }

  try {
    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (users.length > 0) {
      return res.status(400).json({ message: "Email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );

    const token = jwt.sign({ email }, jwtSecret, { expiresIn: "1h" });
    res.status(201).json({ message: "User registered successfully", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});


app.post(
  "/api/google-login",
  passport.authenticate("google-token"),
  (req, res) => {
    res.json(req.user);
  }
);

// Route to get all users
app.get("/api/users", async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, name, email,password FROM users"
    );
    res.status(200).json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

// Route to delete a user by email
app.delete("/api/users", async (req, res) => {
  const { email } = req.body;

  try {
    const [result] = await pool.query("DELETE FROM users WHERE email = ?", [
      email,
    ]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found." });
    }
    res.status(200).json({ message: "User deleted successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Please try again later." });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
