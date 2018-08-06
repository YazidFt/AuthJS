var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;


//User model
var User = require('../models/user');


router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.get('/register', function(req, res, next) {
  res.render('register', {title: 'Register'});
});

router.get('/login', function(req, res, next) {
   res.render('login', {title: 'Login'});
});

router.post('/login',
  passport.authenticate('local', { failureRedirect: '/users/login', 
                                   failureFlash: 'Username or Password is not valid'}),
  function(req, res) {
    req.flash('success', 'You are logged successfully');
    res.redirect('/');
  });


passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
    User.getUserById(id, function(err, user) {
      done(err, user);
    });
  });


passport.use(new LocalStrategy(
    function(username, password, done) {
      User.getUserByUsername(username, function (err, user) {
        if (err) throw err
        if (!user) {
           return done(null, false, { message: 'Unknown user.' });
          }
        
      User.comparePassword(password, user.password, function(err, matched){
           if(err) return done(err);

           if(matched){
              return done(null, user);
            }
           else{
              return done(null, false, { message: 'Invalid Password'});
            } 
          });

      });
    } 
  ));



router.post('/register', function(req, res, next) {
   var name = req.body.name;
   var email = req.body.email;
   var username = req.body.username;
   var password = req.body.password;
   var password2 = req.body.password2;

   //Form validator
   req.checkBody('name', 'Name is required').notEmpty();
   req.checkBody('email', 'Email is not valid').isEmail();
   req.checkBody('username', 'Username is required').notEmpty();
   req.checkBody('password', 'Password is required').notEmpty();
   req.checkBody('password2', 'Passwords do not match').equals(password);


   //check Errors
   var errors = req.validationErrors();
   if(errors){
       res.render('register', {'errors': errors});
    }
   else{
      var user = new User({
          name: name,
          email: email,
          username: username,
          password: password
      });

      User.createUser(user, function(err, user){
             if(err){
               throw err;
             }
             else{ 
                console.log(user);
             }
        });
      
      req.flash('success', 'You are registered successfully')
      
      res.location('/');
      res.redirect('/');
    }
});


router.get('/logout', function(req, res){
    req.logout();
    res.redirect('/users/login');
});

module.exports = router;
