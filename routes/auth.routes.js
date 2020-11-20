const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User.model");
const app = require("../app");
const salt = 10;

const ifAlreadySignedIn = (req, res, next) => {
  if (req.session.user) {
    return res.redirect("/");
  }
  next();
};

const ifNotSignedIn = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/");
  }
  next();
};

router.get("/signup", (req, res) => {
  res.render("signup");
});

router.post("/signup", (req, res) => {
  console.log(req.body);
  const { username, password } = req.body;

  if (!username || password.length < 8) {
    res.render("signup", {
      errorMessage: "Please fill out the form!",
    });
    return;
  }

  User.findOne({ username })
    .then((foundUser) => {
      console.log("foundUser:", foundUser);
      if (foundUser) {
        res.render("signup", {
          errorMessage: "Username already taken",
        });
        return;
      }

      bcrypt
        .genSalt(salt)
        .then((generatedSalt) => {
          return bcrypt.hash(password, generatedSalt);
        })
        .then((hashedPassword) => {
          return User.create({
            username,
            password: hashedPassword,
          });
        })
        .then((userCreated) => {
          console.log("userCreated:", userCreated);
          req.session.user = userCreated;
          res.redirect("/");
        });
    })
    .catch((err) => {
      console.log("err:", err);
      res.render("signup", { errorMessage: err.message });
    });
});

router.get("/login", (req, res) => {
  res.render("login");
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || password.length < 8) {
    res.render("login", {
      errorMessage: "Invalid username and/or password",
    });
    return;
  }
  User.findOne({ username }).then((user) => {
    if (!user) {
      res.render("login", {
        errorMessage: "No such username in the database",
      });

      return;
    }

    bcrypt.compare(password, user.password).then((isSamePassword) => {
      if (!isSamePassword) {
        res.render("login", {
          errorMessage: "Wrong password!",
        });

        return;
      }
      req.session.user = user;
      res.redirect("/");
    });
  });
});

router.get("/main", ifNotSignedIn, (req, res) => {
  res.render("main");
});

router.get("/private", ifNotSignedIn, (req, res) => {
  res.render("private");
});

module.exports = router;
