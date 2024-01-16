const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const expressLayouts = require("express-ejs-layouts");
const db = require("./config/db");
const {
  isAuthenticated,
  ensureNotAuthenticated,
} = require("./middlewares/authMiddleware");

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, //7days
      secure: false,
    },
    secret: "SuperSecretKey",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(
  new LocalStrategy((username, password, done) => {
    // Check if the user exists in the database
    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      (err, rows) => {
        if (err) {
          return done(err);
        }

        if (rows.length === 0) {
          return done(null, false, { message: "Incorrect username." });
        }

        const user = rows[0];

        // Check if the password is correct
        bcrypt.compare(password, user.password, (err, isPasswordValid) => {
          if (err) {
            return done(err);
          }

          if (!isPasswordValid) {
            return done(null, false, { message: "Incorrect password." });
          }

          return done(null, user);
        });
      }
    );
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // Deserialize the user from the database
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => {
    if (err) {
      return done(err);
    }

    if (rows.length === 0) {
      return done(null, false);
    }

    const user = rows[0];
    return done(null, user);
  });
});

// ejs setup
app.set("view engine", "ejs");
app.use(expressLayouts);
app.set("layout", "layouts/main"); // specify the default layout file
// app.use(express.static());
app.use(express.static("public"));

//routes
app.get("/", isAuthenticated, (req, res) => {
  res.render("index", { user: req.user, title: "Home" });
});

// Define a route for the register page
app.get("/register", ensureNotAuthenticated, (req, res) => {
  res.render("register", { title: "Register" });
});

app.post("/register", (req, res) => {
  // Process the form data (you can add your registration logic here)
  const { first_name, last_name, username, email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], (err, users) => {
    if (err) {
      console.log("error in finding user by email");
    } else {
      if (users.length > 0) {
        // Check the length of the users array
        console.log("user already exists, please login by this email");
        res.redirect("/login");
        return;
      } else {
        bcrypt.hash(password, 12, (err, hashedPassword) => {
          if (err) {
            console.log("error in hashing password");
          } else {
            const query =
              "INSERT INTO users(first_name, last_name, username, email, password) VALUES (?,?,?,?,?)";
            const param = [
              first_name,
              last_name,
              username,
              email,
              hashedPassword,
            ];
            db.query(query, param, (err, user) => {
              if (err) {
                console.log("error in creating a user");
              } else {
                // console.log(user);
                res.redirect("/login");
                return; // Add this return statement
              }
            });
          }
        });
      }
    }
  });
});

app.get("/login", ensureNotAuthenticated, (req, res) => {
  res.render("login", { title: "Login" });
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/register",
    failureFlash: true,
  })
);

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

// app.get("/profile", isAuthenticated, (req, res) => {
//   res.render("profile", { user: req.user });
// });

// Start the server
const PORT = 3333;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
