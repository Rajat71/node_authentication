const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const passport = require('passport');


//user model
const User = require('../models/User');

//Login
router.get('/login', (req,res) => res.render('login'));

//Register
router.get('/register', (req,res) => res.render('register'));

//Register Handle
router.post('/register', (req,res) => {
   const {name, email, password, password2 } = req.body; 
   let errors = [];

   //Check required fields
   if(!name || !email || !password || !password2) {
    errors.push({ msg: 'Please fill in all fields'  });
   }

   //Confirm passwords match
   if(password !== password2) {
    errors.push({ msg: 'Passwords do not match'  });
   }

   //Check password length
   if(password.length < 6){
    errors.push({ msg: 'Password should contain at least 6 characters'});
   }

   if(errors.length > 0) {
    res.render('register', {
    errors,
    name,
    email,
    password,
    password2
    });
   } else {
     // after validation 
     User.findOne({ email: email})
       .then(user => {
        if(user) {
            // If user exists
            errors.push({msg: 'Email is already registered'});
            res.render('register',{
                errors,
                name,
                email,
                password,
                password2
             });
            } else {
              const newUser = new User({
                name,
                email,
                password
              });
              bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                  if (err) throw err;
                  newUser.password = hash;
                  newUser
                    .save()
                    .then(user => {
                      req.flash(
                        'success_msg',
                        'You are now registered and can log in'
                      );
                      res.redirect('/users/login');
                    })
                    .catch(err => console.log(err));
               });
             });
            }
          });
        }
      });
        
              
              
              

//Login Handle
router.post('/login',(req, res, next) => {
  passport.authenticate('local',{
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next);

});

 

 // Logout

router.get('/logout', (req, res) => {
  req.logout(req.user, err => {
    if(err) return next(err);
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
  });
});
module.exports = router;