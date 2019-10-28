var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var passportLocalMongoose = require('passport-local-mongoose');
var bcrypt = require('bcrypt-nodejs');

let User = new Schema({
    firstName: {
        type: String,
        unique: false,
        required: true,
        trim: true
      },
    lastName: {
        type: String,
        unique: false,
        required: true,
        trim: true
      },
    phoneNumber: {
        type: String,
        unique: false,
        required: true,
        trim: true
    },
    email: {
      type: String,
      unique: true,
      required: true,
      trim: true
    },
    photoUrl: {
      type: String,
      required: false,
      default: "https://source.unsplash.com/300x300/?nature,water",
      trim: true
    },
    role: {
        type: String,
        required: false
    },
    platform: {
      type: String,
      required: false 
    },
    accessPin: { 
      type: Number,
      required: false 
    }, 
    accessPinExpires: {
      type: Date
    },
    resettingPin: { 
       type: Boolean,
      required: false
    },
    addedOnDate: { 
      type: Date,
      default: Date.now()
    },
    isActive: {
      type: Boolean,
      default: true
    },
    hasAdminPriviledges: {
      type: Boolean,
      default: false,
      required: true
    },
    userRole: {
      type: String,
      default: 'User',//Possible values: User, Admin, Affiliate,
      required: true
    }
  });


// See passport-local-mongoose docs for schema customization options
// https://github.com/saintedlama/passport-local-mongoose#options
User.plugin(passportLocalMongoose, {
    usernameField: 'email',
    usernameUnique: true,
});

// Note: Password is saved to Hash
User.methods.encryptPassword = function(password) {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(5), null);
};

User.methods.validPassword = function(password) {
	return bcrypt.compareSync(password, this.password);
};

module.exports = mongoose.model('User', User);


// Post Send Object Example:
// let sendObject = {
//   "firstName": "John",
//   "lastName": "Doe",
//   "phoneNumber": "5555555555",
//   "email": "john_doe@test.com",
//   "photoUrl": "https://source.unsplash.com/random?water",
//   "userRole": "Admin",
//   "password": "123",
//   "hasAdminPriviledges": false
// }