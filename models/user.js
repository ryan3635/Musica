const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    displayname: String,
    googleId: String,
    token: String,
    tokenExpire: Date,
    awaitingReset: Boolean,
    list: {type: mongoose.Schema.Types.ObjectId, ref: "userList"}
});

const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);

module.exports = User;