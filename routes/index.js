var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', Authenticated ,function(req, res, next) {
  res.render('index', { title: 'Home' });
});


function Authenticated(req, res, next){
     
  if(req.isAuthenticated()){
       return next();
    }
   res.redirect('/users/login');
}


module.exports = router;
