const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const User = require("../models/User.model");

router.get("/signup", (req, res) => {
  res.render("signup");
});

router.post("/signup", (req, res) => {
  console.log(req.body);
  const { username, password } = req.body;

  if (username.length < 5 || password.length < 8) {
    return res.render("signup", {
      errorMessage: "Username or password either omitted or too short",
    });
  }

  User.findOne({ username: username })
    .then((foundUser) => {
      console.log("foundUser:", foundUser);
      if (foundUser) {
        res.render("signup", {
          errorMessage: "Username already taken",
        });
        return;
      }

      const hashingAlgorithm = bcrypt.genSaltSync(10);
      console.log("hashingAlgorithm:", hashingAlgorithm);
      const hashedPassword = bcrypt.hashSync(password, hashingAlgorithm);

      User.create({
        username,
        password: password,
      }).then((userCreated) => {
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
  if (username === "" || password === "") {
    res.render("login", {
      errorMessage: "Please enter both username and password to login.",
    });
    return;
  }

  User.findOne({ username }).then((foundUser) => {
    if (!foundUser) {
      res.render("login", {
        errorMessage: "Username not in the database.",
      });
      return;
    } else if (bcrypt.compareSync(password, foundUser.passwordHash)) {
      res.render("user-profile", { foundUser });
    } else {
      res.render("login", { errorMessage: "Incorrect password." });
    }
  });
});

module.exports = router;
