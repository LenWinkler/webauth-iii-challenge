const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Users = require('../users/users-model.js');
const { validateUser } = require('../users/users-helpers.js')