require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");

const mongoose = require("mongoose");
const mongodb = require("mongodb").MongoClient;
const findOrCreate = require('mongoose-findorcreate');
const { Db } = require('mongodb');

const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/musicaDB", { useNewUrlParser: true, useUnifiedTopology: true });  //update this when posted online

const userLoginSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});

userLoginSchema.plugin(passportLocalMongoose);
userLoginSchema.plugin(findOrCreate);
const UserLogin = new mongoose.model("UserLogin", userLoginSchema);
passport.use(UserLogin.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    UserLogin.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/userHome",  //update this when posted online
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        //console.log(profile);
        UserLogin.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", function (req, res) {
    res.render("home");
});


app.get("/login", function (req, res) {
    res.render("login");
});


app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});


app.get("/register", function (req, res) {
    res.render("register");
});


app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);


app.get("/auth/google/userHome",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect("/userHome");
    });


app.get("/userHome", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("userHome");
    } else {
        res.redirect("/login");
    }
});


app.get("/userProfile", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("userProfile");
    } else {
        res.redirect("/login");
    }
});


app.post("/login", function (req, res) {
    const user = new UserLogin({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/userHome");
            });
        }
    });
});


app.post("/register", function (req, res) {
    UserLogin.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/userHome");
            });
        }
    });
});


app.post("/userProfile", function (req, res) {
    //todo
});


app.listen(3000, function () {
    console.log("Server started!");
});