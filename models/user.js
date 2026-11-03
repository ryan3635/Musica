const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    displayname: String,
    googleId: String,
    token: String,
    tokenExpire: Date,
    awaitingReset: Boolean
});

const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

userSchema.index({username: 1}, {unique: true, sparse: true});
userSchema.index({displayname: 1}, {unique: true, sparse: true});
userSchema.index({googleId: 1}, {unique: true, sparse: true});

const User = new mongoose.model("User", userSchema);
module.exports = User;