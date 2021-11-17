const router = require("express").Router();
const isLoggedIn = require("./../middleware/is.logged.in");

/* GET / - home page */
router.get("/", (req, res, next) => {
  let isUser = false;
  if (req.session.user) {
    isUser = true;
  }
  res.render("index", { isUser });
});

// GET / secret image
router.get("/secret-main", isLoggedIn, (req, res) => {
  res.render("secret-main");
});

// GET / secret gif
router.get("/secret-gif", isLoggedIn, (req, res) => {
  res.render("secret-gif");
});

module.exports = router;
