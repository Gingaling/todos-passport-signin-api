var express = require('express');
var passport = require('passport');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');
var db = require('../db');


passport.use(new LocalStrategy(function verify(username, password, cb) {
    db.get('SELECT * FROM users WHERE username = ?', [username], function(err, row) {
        if (err) { return cb(err); }
        if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
        
        crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
            if (err) { return cb(err); }
            return !crypto.timingSafeEqual(row.hashed_password, hashedPassword) ? cb(null, false, { message: 'Incorrect username or password.' }) : cb(null, row);
        });
    });
}));


passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, { id: user.id, username: user.username });
	});
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
	});
});

var router = express.Router();

router.get('/login', function(req, res, next) {
	res.render('login');
});

router.post('/login/password', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureMessage: true
}));

router.post('/logout', function(req, res, next) {
	req.logout(function(err) {
		if (err) { return next(err); }
		res.redirect('/');
	});
});

router.get('/signup', function(req, res, next) {
	res.render('signup');
});

router.post('/signup', function(req, res, next) {
	var salt = crypto.randomBytes(16);
	crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
        if (err) { return next(err); }
		db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
            req.body.username,
            hashedPassword,
            salt
        ], function(err) {
            if (err) { return next(err); }
            let user = {
                id: this.lastID,
                username: req.body.username
            };
            req.login(user, function(err) {
                if (err) { return next(err); }
                res.redirect('/');
            });
        });
	});
});

module.exports = router;
