"use strict";
const mongoose = require("mongoose");
const dbConnection =
  "mongodb+srv://anmongosedb:anmongosedb@cluster0.fgygpzz.mongodb.net/authn?retryWrites=true&w=majority";

mongoose.connect(dbConnection);
const db = mongoose.connection;

db.on("error", () => {
  console.log("> error occurred from the database");
});
db.once("open", () => {
  console.log("> successfully opened the database");
});
module.exports = mongoose;
