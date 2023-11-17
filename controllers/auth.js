import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

import User from "../models/user.js";
import HttpError from "../helpers/HttpError.js";
import ctrlWrapper from "../helpers/ctrlWrapper.js";

dotenv.config();

const { SECRET_KEY } = process.env;

const accessTokenExpires = "24h";

const signUp = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user) {
    throw HttpError(409, "Email in use");
  }
  const hashPassword = await bcrypt.hash(password, 10);

  const newUser = await User.create({
    ...req.body,
    password: hashPassword,
  });

  const payload = {
    id: newUser._id,
  };

  const accessToken = jwt.sign(payload, SECRET_KEY, {
    expiresIn: accessTokenExpires,
  });

  await User.findByIdAndUpdate(newUser._id, { accessToken });

  res.status(201).json({
    accessToken,
    user: {
      email: newUser.email,
    },
  });
};

const signIn = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!user || !passwordCompare) {
    throw HttpError(401, "Email  or password is wrong");
  }

  const payload = {
    id: user._id,
  };

  if (!user || !passwordCompare) {
    throw HttpError(401, "Email  or password is wrong");
  }

  const accessToken = jwt.sign(payload, SECRET_KEY, {
    expiresIn: accessTokenExpires,
  });

  await User.findByIdAndUpdate(user._id, { accessToken });
  res.json({
    accessToken,
    user: { email: user.email },
  });
};

const logoutUser = async (req, res) => {
  const { _id } = req.user;
  await User.findByIdAndUpdate(_id, { accessToken: "" });
  res.status(204).json();
};

const getRefreshToken = async (req, res, next) => {
  const { refreshToken: token } = req.body;
  try {
    const { id } = jwt.verify(token, REFRESH_SECRET_KEY);

    const isExist = await User.findOne({ refreshToken: token });
    if (!isExist) {
      next(HttpError(403), "Token invalid");
    }

    const payload = {
      id,
    };

    const accessToken = jwt.sign(payload, ACCESS_SECRET_KEY, {
      expiresIn: accessTokenExpires,
    });

    res.json({ accessToken });
  } catch (error) {
    next(HttpError(403), error.message);
  }
};

const getCurrentUser = async (req, res) => {
  const { email, accessToken } = req.user;
  console.log(req.user);

  res.json({
    email,
    accessToken,
  });
};

export default {
  signUp: ctrlWrapper(signUp),
  signIn: ctrlWrapper(signIn),
  getCurrentUser: ctrlWrapper(getCurrentUser),
  logoutUser: ctrlWrapper(logoutUser),
  getRefreshToken: ctrlWrapper(getRefreshToken),
};
