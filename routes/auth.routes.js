const router = require("express").Router();
const User = require("./../models/User.model");
const bcrypt = require("bcryptjs");
const isLoggedIn = require("./../middleware/is.logged.in");

const SALT_ROUNDS = 10;

// ROUTES:
// GET /signup
router.get("/signup", (req, res) => {
  res.render("auth/signup-form");
});

// POST /signup
router.post("/signup", (req, res) => {
  // * STEP 1. Get password and username from req.body
  const { username, password } = req.body;

  // * STEP 2. Check if username and password are provided on the signup form
  const usernameNotProvided = !username || username === "";
  const passwordNotProvided = !password || password === "";

  if (usernameNotProvided || passwordNotProvided) {
    res.render("auth/signup-form", { errorMessage: "Provide username and password" });

    return;
  }

  // *   Step 8. check the password strength (optional) - USING REGEX
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;

  if (!regex.test(password)) {
    res.status(400).render("auth/signup-form", {
      errorMessage:
        "Password needs to have at least 8 chars and must contain at least one number, one lowercase and one uppercase letter.",
    });
    return;
  }

  // * STEP 3. Check if the username is not taken and create the user if not
  User.findOne({ username })
    .then((foundUser) => {
      if (foundUser) {
        throw new Error("The username already exists");
      }
      // * Step 4. Using a bcrypt method generate the 'salt string'
      return bcrypt.genSalt(SALT_ROUNDS);
    })
    .then((salt) => {
      // * Step 5. Encrypt/hash the password
      return bcrypt.hash(password, salt);
    })
    .then((hashedPassword) => {
      // * Step 6. Create new user
      return User.create({ username, password: hashedPassword });
    })
    .then((createdUser) => {
      // * Step 7. Redirect user to home '/' page after the successful signup
      res.redirect("/");
    })
    .catch((err) => {
      res.render("auth/signup-form", { errorMessage: err.message || "Error while trying to sign up" });
    });
});

// GET /login
router.get("/login", (req, res) => {
  res.render("auth/login-form");
});

// POST /login
router.post("/login", (req, res) => {
  // * Step 1. Get password and username from form req.body
  const { username, password } = req.body;

  // * Step 2. Check if username and password are provided on form
  const usernameNotProvided = !username || username === "";
  const passwordNotProvided = !password || password === "";

  if (usernameNotProvided || passwordNotProvided) {
    res.render("auth/login-form", { errorMessage: "Provide username and password" });

    return;
  }
  // * Step 3. Check if user exists
  let user;
  User.findOne({ username })
    .then((foundUser) => {
      user = foundUser;
      if (!foundUser) {
        throw new Error("Wrong credentials");
      }
      // * Step 4. Compare the passwords
      return bcrypt.compare(password, foundUser.password);
    })
    // * Step 5. Check if password is correct
    .then((isCorrectPassword) => {
      if (!isCorrectPassword) {
        throw new Error("Wrong credentials");
      } else if (isCorrectPassword) {
        // * Step 6. Create the session + cookie and redirect the user
        req.session.user = user;
        res.redirect("/");
      }
    })
    .catch((err) => {
      res.render("auth/login-form", { errorMessage: err.message || "Error while trying to login" });
    });
});

// POST /logout
router.get("/logout", isLoggedIn, (req, res) => {
  // delete the session from the sessions collection from DB
  // this automatically invalidates the future request with the same cookie
  req.session.destroy((err) => {
    if (err) {
      return res.render("error");
    }
    // if the session was deleted with success redirect user to home page
    res.redirect("/");
  });
});

module.exports = router;
