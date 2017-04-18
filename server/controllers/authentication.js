const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
	const timestamp = new Date().getTime();
	return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signup = function(req, res, next) {
	const { email, password } = req.body;

	if (!email || !password) {
		return res.status(422).send({ error: 'You must provide email and password' });
	}

	// See if a user with given email exists
	User.findOne({ email }, function(err, existingUser) {
		if (err) { return next(err); }

		if (existingUser) {
			return res.status(422).send({ error: 'Email is in use' });
		}

		const user = new User({
			email,
			password
		});

		user.save(function(err) {
			if (err) { return next(err); }
			res.json({ token: tokenForUser(user) });
		});

	});
}