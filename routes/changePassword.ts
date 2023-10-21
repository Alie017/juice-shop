/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

const { User } = require('./user-model'); 
const bcrypt = require('bcrypt'); 

  module.exports = function changePassword() {
  return async (req, res, next) => {
    const { query, headers, user, connection } = req;
    const currentPassword = query.current;
    const newPassword = query.new;
    const repeatPassword = query.repeat;

    try {
      // a more relevant solution to make the auhentication in a more secure way ( Hopefully :) )
      if (!user) { 
      return res.status(401).json({ message: 'Unauthorized. Please log in.' });
      }

      const passwordMatches = await bcrypt.compare(currentPassword, user.password);
      if (!passwordMatches) {
        return res.status(401).json({ message: 'Current password is incorrect.' });
      }
      // Tried to use a simple mechanism to check whether the password of the user matches the current password

      if (newPassword !== repeatPassword) {
        return res.status(400).json({ message: 'New and repeated password do not match.' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10); 
      user.password = hashedPassword;
      await user.save();
      // I've tried to use hashing 

      return res.status(200).json({ message: 'Password changed successfully.' });
    } catch (error) {
      
      console.error(error);
      return res.status(500).json({ message: 'An error occurred while changing the password.' });
    }
  };
};
