const mongoose = require("../db");
const { schemaOptions } = require("./modelOptions");
const User = mongoose.model(
  "User",
  new mongoose.Schema(
    {
      id: {
        type: String,
      },
      name: {
        type: String,
        unique: false,
      },
      email: {
        type: String,
      },
      authenticators: {
        type: Array,
      },
      registered: {
        type: Boolean,
        default: false,
      },
      role: {
        type: String,
      },
      otp: {
        type: String,
        default: false,
      },
    },
    schemaOptions
  )
);

module.exports = User;
