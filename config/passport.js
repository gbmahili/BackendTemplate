var passport = require('passport');
var User = require('../models/User');
var LocalStrategy = require('passport-local').Strategy;

passport.serializeUser(function(user, done) {
	done(null, user.id);
});

passport.deserializeUser(function(id, done) {
	User.findById(id, function(err, user) {
		done(err, user);
	})
});

passport.use('local.signup', new LocalStrategy({
	usernameField: 'email',
	firstnameField: 'firstName',
	lastnameField: 'lastName',
	passwordField: 'password',
	passReqToCallback: true
}, function(req, email, password, done) {
	console.log("strategy");
	req.checkBody('email', 'Invalid email').notEmpty().isEmail();
	req.checkBody('password', 'Invalid password').notEmpty().isLength({min:4});
	req.checkBody('firstName', 'Please enter your first name').notEmpty();
	req.checkBody('lastName', 'Please enter your last name').notEmpty();
	var errors = req.validationErrors();
	if(errors) {
		var messages = [];
		errors.forEach(function(error) {
			messages.push(error.msg);
		});
		return done(null, false, req.flash('error', messages));
	}
	User.findOne({'email': email}, function(err, user) {
		if(err) {
			return done(err);
		}
		if(user) {
			return done(null, false, {message: 'Email is already in use.'});
		}
		var newUser = new User();
		newUser.email = email;
		newUser.password = newUser.encryptPassword(password);
		newUser.firstName = req.body.firstName;
		newUser.lastName = req.body.lastName;
		newUser.save(function(err, result) {
			if(err) {
				return done(err);
			}
			return done(null, newUser);
		});
	});
}));

passport.use('local.signin', new LocalStrategy({
	usernameField: 'email',
	passwordField: 'password',
	passReqToCallback: true
}, function(req, email, password, done) {
	req.session.email = req.body.email;
	req.checkBody('email', 'Invalid email').notEmpty().isEmail();
	req.checkBody('password', 'Invalid password').notEmpty();
	var errors = req.validationErrors();
	if(errors) {
		var messages = [];
		errors.forEach(function(error) {
			messages.push(error.msg);
		});
		return done(null, false, req.flash('error', messages));
	}
	User.findOne({'email': email}, function(err, user) {
		if(err) {
			return done(err);
		}
		if(!user) {
			return done(null, false, {message: 'No user found.'});
		}
		if (!user.validPassword(password)) {
			return done(null, false, {message: 'Incorrect password.'});
		}
		req.session.firstName = user.firstName;
		req.session.lastName = user.lastName;
		return done(null, user);
	});
}));

passport.use('local.admin', new LocalStrategy({
	usernameField: 'email',
	passwordField: 'password',
	passReqToCallback: true
}, function(req, email, password, done) {
	req.session.email = req.body.email;
	req.checkBody('email', 'Invalid email').notEmpty().isEmail();
	req.checkBody('password', 'Invalid password').notEmpty();
	var errors = req.validationErrors();
	if(errors) {
		var messages = [];
		errors.forEach(function(error) {
			messages.push(error.msg);
		});
		return done(null, false, req.flash('error', messages));
	}
	User.findOne({'email': email}, function(err, user) {
		if(err) {
			return done(err);
		}
		if(!user) {
			return done(null, false, {message: 'No user found.'});
		}
		if (!user.validPassword(password)) {
			return done(null, false, {message: 'Incorrect password.'});
		}
		return done(null, user);
	});
}));