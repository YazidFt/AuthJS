var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');


mongoose.connect('mongodb://localhost/nodeauth');
var db = mongoose.connection;


var UserSchema = mongoose.Schema({

     username: {
         type: String,
         index: true
     },
     password: {
         type: String
     },
     email: {
         type: String
     },
     name: {
         type: String
     }
});

var User = module.exports  = mongoose.model('User', UserSchema);

module.exports.createUser = function(newUser, callback){
        bcrypt.genSalt(10, function(err, salt) {
            bcrypt.hash(newUser.password, salt, function(err, hash) {
                 newUser.password = hash;
                 newUser.save(callback);
                });
            });
   }

module.exports.getUserById = function(id, callback){
        User.findById(id, callback);
   }

module.exports.getUserByUsername = function(username, callback){
        User.findOne({username: username}, callback);
   }

module.exports.comparePassword = function(InPassword, hash, callback){
    bcrypt.compare(InPassword, hash, function(err, matched) {
           callback(null, matched);
      });
   }