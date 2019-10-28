const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const keys = require('./../config/keys');
let secret = keys.secretKey;

// Register User
// Route: /user/registerUser
// Params: firstName, lastName, phoneNumber, email, photoUrl, hasAdminPriviledges, userRole, password
router.post('/registerUser', function (req, res) {
  let { firstName, lastName, phoneNumber, email, photoUrl, hasAdminPriviledges, userRole } = req.body;
  email = email.toLowerCase();
  let password = req.body.password;
  let newUser = { firstName, lastName, phoneNumber, email, photoUrl, hasAdminPriviledges, userRole };
  User.register(
    new User(newUser),
    password,
    function (err, user) {
      if (err) {
        console.log("ERROR", err);
        res.status(400).send({ error: err.message })
      } else {
        let resUser = { ...user._doc };
        let token = jwt.sign({ id: user._id, email: user.email }, secret);
        resUser.token = token;
        // Delete valuable keys
        delete resUser.salt;
        delete resUser.hash;
        delete resUser.__v;
        res.status(200).json(resUser);
      }
    });
});

// Login 
// Route: /user/loginUser
// Params: { username, password }
router.post('/loginUser', function (req, res, next) {
  passport.authenticate('local', function (err, user, info) {

    if (err) {
      console.log("Error: ", err);
      res.status(400).json({ error: err.message});
    }

    if (!user) {
      console.log("Passport Error: ", info.message);
      return res.status(401).json({ error: info.message });
    }

    if (user.isActive) {
      User
        .findById(user._id)
        .then((dbModel) => {
          let resUser = { ...dbModel._doc };
          let token = jwt.sign({ id: user._id, email: user.email }, secret);
          resUser.token = token;
          // Delete valuable keys
          delete resUser.salt;
          delete resUser.hash;
          delete resUser.__v;
          res.status(200).json(resUser);
        })
        .catch((err) => {
          console.log("Error: ", err);
          res.status(422).json(err);
        });
    } else {
      res.status(400).json({ error: "Access Restricted" });
    }
  })(req, res, next);
});

module.exports = router;