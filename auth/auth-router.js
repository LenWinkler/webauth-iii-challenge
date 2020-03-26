const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Users = require('../users/users-model.js');
const { validateUser } = require('../users/users-helpers.js');

router.post('/register', (req, res) => {
    let user = req.body;

    const validateResult = validateUser(user);

    if (validateResult.isSuccessful === true) {
        const hash = bcrypt.hashSync(user.password, 12);
        user.password = hash;

        Users.add(user)
          .then(saved => {
              res.status(201).json(saved)
          })
          .catch(err => {
              res.status(500).json(err)
          });
    } else {
        res.status(400).json({
            message: 'Invalid user info. See errors',
            errors: validateResult.errors
        });
    }
});

router.post('/login', (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {

                const token = getJwtToken(user.username);

                res.status(200).json({
                    message: `Welcome, ${user.username}! Here's your token.`,
                    token
                });
            } else {
                res.status(400).json({ message: 'Invalid credentials' });
            }
        })
        .catch(err => {
            res.status(500).json(err)
        });
});

function getJwtToken(username) {

    Users.findBy({ username })
        .first()
        .then(user => {
            return user
        })
        .catch(err => {
            console.log(err)
        })

    const payload = {
        id: user.id,
        username: user.username,
        department: user.department
    }

    const secret = process.env.JWT_SECRET || 'super secret';

    const options = {
        expiresIn: '1hr'
    };

    return jwt.sign(payload, secret, options)
}

module.exports = router;