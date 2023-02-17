require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const Discogs = require("disconnect").Client;
var db = new Discogs({consumerKey: process.env.DISCOGS_API_KEY, consumerSecret: process.env.DISCOGS_SECRET}).database();

const mongoose = require("mongoose");
const mongodb = require("mongodb").MongoClient;
const findOrCreate = require("mongoose-findorcreate");
const { Db } = require("mongodb");

const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.authenticate("session"));

mongoose.set("strictQuery", false);
mongoose.connect("mongodb://localhost:27017/musicaDB", {useNewUrlParser: true, useUnifiedTopology: true});  //update this when posted online

const userListSchema = new mongoose.Schema({
    albumID: Number,
    title: String,
    year: String,
    img: String,
    albumTracks: [String]
});

const userList = new mongoose.model("List", userListSchema);

const userLoginSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
});

userLoginSchema.plugin(passportLocalMongoose);
userLoginSchema.plugin(findOrCreate);
const UserLogin = new mongoose.model("UserLogin", userLoginSchema);

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser (function (id, done) {
    UserLogin.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new LocalStrategy (function (username, password, done) {
    UserLogin.findOne({username: username}, function (err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);

        bcrypt.compare(password, user.password, function (err, res) {
            if (err) return done(err);
            if (res === false) return done(null, false);
            return done(null, user);
        });
    });
}));

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/userHome",  //update this when posted online
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, done) {
        UserLogin.findOrCreate({googleId: profile.id}, function (err, user) {
            return done(err, user);
        });
    }
));


app.get("/", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("userHome");
    } else {
        res.render("home");
    }
});


app.get("/login", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("loggedIn");
    } else {
        const errCheck = {
            page: "Login",
            error: req.query.error,
            accCreated: req.query.accCreated
        };
        res.render("login", errCheck);
    }
});


app.get("/register", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("loggedIn");
    } else {
        const errCheck = {
            page: "Register",
            error: req.query.error
        };
        res.render("register", errCheck);
    }
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


app.get("/loggedIn", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("loggedIn");
    } else {
        res.redirect("/login");
    }
});


app.get("/auth/google",
    passport.authenticate('google', {scope: ["profile"]})
);


app.get("/auth/google/userHome",
    passport.authenticate('google', {failureRedirect: "/login"}),
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
        userList.find({}, function (err, results) {
            if (err) console.log(err);
            else {
                res.render("userProfile", {
                    albumList: results,
                });
            }
        });
    } else {
        res.redirect("/login");
    }
});


app.post("/login", passport.authenticate("local", {successRedirect: "/userHome", failureRedirect: "/login?error=true"}));


app.post("/register", function (req, res) {
    if (req.body.username === "" || req.body.password === "") res.redirect("/register?error=true");
    else if (req.isAuthenticated()) res.redirect("/loggedIn");
    else {
        bcrypt.genSalt(10, function (err, salt) {
            if (err) return next(err);
            bcrypt.hash(req.body.password, salt, function (err, hash) {
                if (err) res.redirect("/register?error=true");
    
                const newUser = new UserLogin({
                    username: req.body.username,
                    password: hash
                });
                newUser.save();
                res.redirect("/login?accCreated=true");
            });
        });
    }
});


app.post("/userProfile", function (req, res) {
    if (req.isAuthenticated()) {
        const artistName = req.body.userArtist;
        const albumName = req.body.userAlbum;
        const albumYear = req.body.year;
        db.search({artist: artistName, release_title: albumName, year: albumYear, type: "master"}).then(function (searchResult) {
            albumInfo = "";
            year = "";
            imgURL = "";
            var albumID1 = 99999999999999;
            var albumID2 = 99999999999999;

            if (searchResult.results.length > 0) {
                console.log(searchResult);

                var i = searchResult.results.findIndex(album => album.country === "US");
                var posUS = 0;

                while (i >= 0 && i < searchResult.results.length - 1) {
                    const albumID1temp = searchResult.results[i].master_id;
                    if (albumID1temp < albumID1 && searchResult.results[i].country === "US") {
                        albumID1 = albumID1temp;
                        posUS = i;
                    }
                    i++;
                }
                // if (i >= 0) {
                //     albumID1 = searchResult.results[i].master_id;
                //     if (i < searchResult.results.length - 1) {
                //         var temp1 = searchResult.results.findIndex((album, pos) => pos > i && album.country === "US");
                //         if (temp1 != -1 && searchResult.results[temp1].master_id < albumID1) {
                //             albumID1 = searchResult.results[temp1].master_id;
                //             i = temp1;
                //         }
                //     }
                // }

                var j = searchResult.results.findIndex(album => album.country === "UK");
                var posUK = 0;

                while (j >= 0 && j < searchResult.results.length - 1) {
                    const albumID2temp = searchResult.results[j].master_id;
                    if (albumID2temp < albumID2 && searchResult.results[j].country === "UK") {
                        albumID2 = albumID2temp;
                        posUK = j;
                    } 
                    j++;
                }
                // if (j >= 0) {
                //     albumID2 = searchResult.results[j].master_id;
                //     if (j < searchResult.results.length - 1) {
                //         var temp2 = searchResult.results.findIndex((album, pos) => pos > j && album.country === "UK");
                //         if (temp2 != -1 && searchResult.results[temp2].master_id < albumID2) {
                //             albumID2 = searchResult.results[temp2].master_id;
                //             j = temp2;
                //         }
                //     }
                // }

                if (albumID1 < albumID2) {
                    albumInfo = searchResult.results[posUS].title;
                    year = "(" + searchResult.results[posUS].year + ")";
                    imgURL = searchResult.results[posUS].cover_image;

                    const tracklist = new Array();
                    db.getMaster(albumID1, function(err, data){
                        console.log(data);
                        var trackNumber = 0;
                        for (i = 0; i < data.tracklist.length; i++) {
                            if (data.tracklist[i].type_ != 'heading' && data.tracklist[i].position != 'Video') {
                                trackNumber++;
                                if (data.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + data.tracklist[i].title);
                                else tracklist.push(trackNumber + ". " + data.tracklist[i].title + " (" + data.tracklist[i].duration + ")");
                            }
                        }
                        const album = new userList({
                            albumID: albumID1,
                            title: albumInfo,
                            year: year,
                            img: imgURL,
                            albumTracks: tracklist
                        });
                        album.save();
                    });
                    
                } else if (albumID1 > albumID2) {
                    albumInfo = searchResult.results[posUK].title;
                    year = "(" + searchResult.results[posUK].year + ")";
                    imgURL = searchResult.results[posUK].cover_image;

                    const tracklist = new Array();
                    db.getMaster(albumID2, function(err, data){
                        console.log(data);
                        var trackNumber = 0;
                        for (i = 0; i < data.tracklist.length; i++) {
                            if (data.tracklist[i].type_ != 'heading' && data.tracklist[i].position != 'Video') {
                                trackNumber++;
                                if (data.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + data.tracklist[i].title);
                                else tracklist.push(trackNumber + ". " + data.tracklist[i].title + " (" + data.tracklist[i].duration + ")");
                            }
                        }
                        const album = new userList({
                            albumID: albumID2,
                            title: albumInfo,
                            year: year,
                            img: imgURL,
                            albumTracks: tracklist
                        });
                        album.save();
                    });

                } else {
                    albumInfo = searchResult.results[0].title;
                    year = "(" + searchResult.results[0].year + ")";
                    imgURL = searchResult.results[0].cover_image;
                    albumID1 = searchResult.results[0].master_id;

                    const tracklist = new Array();
                    db.getMaster(albumID1, function(err, data){
                        console.log(data);
                        var trackNumber = 0;
                        for (i = 0; i < data.tracklist.length; i++) {
                            if (data.tracklist[i].type_ != 'heading' && data.tracklist[i].position != 'Video') {
                                trackNumber++;
                                if (data.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + data.tracklist[i].title);
                                else tracklist.push(trackNumber + ". " + data.tracklist[i].title + " (" + data.tracklist[i].duration + ")");
                            }
                        }
                        const album = new userList({
                            albumID: albumID1,
                            title: albumInfo,
                            year: year,
                            img: imgURL,
                            albumTracks: tracklist
                        });
                        album.save();
                    });
                }

                setTimeout(function () {
                    res.redirect("userProfile");
                }, 1000);
            }
            else {
                res.redirect("userProfile");
            }
        });
    }
});


app.listen(3000, function () {
    console.log("Server started!");
});