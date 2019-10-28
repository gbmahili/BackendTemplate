const app = require('express')();
const server = require('http').Server(app);
const io = require('socket.io')(server);
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');

const logger = require('morgan');
const cookieParser = require('cookie-parser');

const session = require('express-session');
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('connect-flash');
const validator = require('express-validator');
const MongoStore = require('connect-mongo')(session);
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('./models/User');
const keys = require('./config/keys');

const users = require('./routes/users');

// const app = express();
const port = process.env.PORT || 6060;
// JWT configration
const options = {}
options.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme("jwt");
options.secretOrKey = keys.secretKey;

app.use(passport.initialize());

require('./config/passport');

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(validator());
app.use(session({
  secret: 'mysecretsession',
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({ mongooseConnection: mongoose.connection }),
  cookie: { maxAge: 18 * 60 * 60 * 1000 }
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.resolve(__dirname, "client/build")));

// Configure Passport to use local strategy for initial authentication.
passport.use('local', new LocalStrategy(User.authenticate()));

// Configure Passport to use JWT strategy to look up Users.
passport.use('jwt', new JwtStrategy(options, function (jwt_payload, done) {
  User.findOne({
    _id: jwt_payload.id
  }, function (err, user) {
    if (err) {
      return done(err, false);
    }
    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  })
}))

app.use(function (req, res, next) {
  res.locals.login = req.isAuthenticated();
  res.locals.session = req.session;
  next();
});

// Socket.io routes
// require('./routes/socket_io')(io);
app.use('/user', users);


// connect to database
const db = keys.mongoDB.LOCAL;
mongoose.Promise = Promise;
let mongooseOptions = { 
  'useCreateIndex': true,
  'useNewUrlParser': true,
  'useUnifiedTopology': true,
  'useFindAndModify': false
};
mongoose.connect( db, mongooseOptions, () => {
  console.log('----- Server successfully connected to MongoDB on: { LOCAL } -----');
});
mongoose.connection.on('error', function () {
  console.log('----- Error: Server could not connect to MongoDB. ----- ');
});

// All other routes
app.get("*", (req, res) => {
  res.sendFile(path.resolve(__dirname, "client/build", "index.html"));
});

app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.json({
    message: err.message,
    error: {},
    err
  });
});

server.listen(port, () => {
  console.log(`----- Server started on: { http://localhost:${port} } ---------------`);
});