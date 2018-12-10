const express = require("express");
const passport = require('passport');
const router = express.Router();
const User = require("../models/User");
const parser = require("../config/cloudinary");

// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;


router.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, theUser, failureDetails) => {
        if (err) {
            res.status(500).json({ message: 'Something went wrong authenticating user' });
            return;
        }
    
        if (!theUser) {
            // "failureDetails" contains the error messages
            // from our logic in "LocalStrategy" { message: '...' }.
            res.status(401).json(failureDetails);
            return;
        }

        // save user in session
        req.login(theUser, (err) => {
            if (err) {
                res.status(500).json({ message: 'Session save went bad.' });
                return;
            }

            // We are now logged in (that's why we can also send req.user)
            res.status(200).json(theUser);
        });
    })(req, res, next);
});

router.post('/signup', (req, res, next) => {
  const {username, password, campus, course} = req.body;

  if (!username || !password) {
    res.status(400).json({ message: 'Provide username and password' });
    return;
  }

  if(password.length < 7){
      res.status(400).json({ message: 'Please make your password at least 8 characters long for security purposes.' });
      return;
  }

  User.findOne({ username }, (err, foundUser) => {

      if(err){
          res.status(500).json({message: "Username check went bad."});
          return;
      }

      if (foundUser) {
          res.status(400).json({ message: 'Username taken. Choose another one.' });
          return;
      }

      const salt     = bcrypt.genSaltSync(10);
      const hashPass = bcrypt.hashSync(password, salt);

      const newUser = new User({
          username:username,
          password: hashPass,
          campus: campus,
          course: course
      });

      newUser.save(err => {
          if (err) {
              res.status(400).json({ message: 'Saving user to database went wrong.' });
              return;
          }
          
          // Automatically log in user after sign up
          // .login() here is actually predefined passport method
          req.login(newUser, (err) => {

              if (err) {
                  res.status(500).json({ message: 'Login after signup went bad.' });
                  return;
              }
          
              // Send the user's information to the frontend
              // We can use also: res.status(200).json(req.user);
              res.status(200).json(newUser);
          });
      });
  });
});

router.get('/logout', (req, res, next) => {
  // req.logout() is defined by passport
  req.logout();
  res.status(200).json({ message: 'Log out success!' });
});

router.get('/loggedin', (req, res, next) => {
  // req.isAuthenticated() is defined by passport
  if (req.isAuthenticated()) {
      res.status(200).json(req.user);
      return;
  }
  res.status(403).json({ message: 'Unauthorized' });
});


router.post("/upload", parser.single("picture"), (req, res) => {
  User.findByIdAndUpdate(req.user.id, { image: req.file.url })
  .then(() => {
    res.json({
      success: true,
      pictureUrl: req.file.url
    });
  })
  .catch ((err)=>{
    res.json({
      success: false
    });
    return err
  })
});


router.post("/edit", (req, res) => {
  const { username, password, campus, course } = req.body;

  const myUser = {};

  if (username) {
    myUser.username = username;
  }

  if (campus) {
    myUser.campus = campus;
  }

  if (course) {
    myUser.course = course;
  }

  User.findByIdAndUpdate(req.user.id, myUser).then(() => {
    res.json({
      success: true,
      myUser
    });
  });
});



module.exports = router;
