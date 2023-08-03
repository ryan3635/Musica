require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
var async = require("async");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const Discogs = require("disconnect").Client;
var db = new Discogs({consumerKey: process.env.DISCOGS_API_KEY, consumerSecret: process.env.DISCOGS_SECRET}).database();

const emailer = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.NODEMAILER_USER,
        pass: process.env.NODEMAILER_PASS
    }
});

const mongoose = require("mongoose");
const mongodb = require("mongodb").MongoClient;
const { Db } = require("mongodb");

const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
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
const User = require("./models/user");
const Album = require("./models/album");

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser (function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new LocalStrategy (function (username, password, done) {
    User.findOne({username: username}, function (err, user) {
        if (err) return done(err);
        else if (!user) return done(null, false);

        bcrypt.compare(password, user.password, function (err, res) {
            if (err) return done(err);
            else if (res === false) return done(null, false);
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
        User.findOrCreate({googleId: profile.id}, function (err, user) {
            return done(err, user);
        });
    }
));


app.get("/", function (req, res) {
    if (req.isAuthenticated()) {
        if (req.user.displayname === undefined) res.redirect("/change/displayname");
        else {
            const logged = {
                loggedIn: req.query.loggedIn,
                googleDisplayname: req.query.googleDisplayname
            }
            res.render("userHome", logged);
        }
    } else res.render("home", {loggedOut: false});
});


app.get("/login", function (req, res) {
    if (req.isAuthenticated()) res.render("loggedIn");
    else {
        const errCheck = {
            page: "Login",
            error: req.query.error,
            accCreated: req.query.accCreated,
            pwReset: req.query.pwReset
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
            error: req.query.error,
            duplicatePwError: req.query.duplicatePwError,
            duplicateEmail: req.query.duplicateEmail,
            duplicateDisplayname: req.query.duplicateDisplayname
        };
        res.render("register", errCheck);
    }
});


app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) console.log(err);
        else res.render("home", {loggedOut: true});
    });
});


app.get("/loggedIn", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("loggedIn");
    } else {
        res.redirect("/login");
    }
});


app.get("/account", function (req, res) {
    if (req.isAuthenticated()) {
        if (req.user.googleId === undefined) {
            const message = {
                displaynameUpdate: req.query.displaynameUpdate,
                emailUpdate: req.query.emailUpdate,
                passwordUpdate: req.query.passwordUpdate,
                googleAcc: false
            }
            res.render("account", message);
        }
        else if (req.user.googleId !== undefined) {
            const message = {
                displaynameUpdate: req.query.displaynameUpdate,
                emailUpdate: req.query.emailUpdate,
                passwordUpdate: req.query.passwordUpdate,
                googleAcc: true
            }
            res.render("account", message);
        } else res.redirect("/account");
    }
    else res.redirect("/login");
});


app.get("/forget", function (req, res) {
    if (!req.isAuthenticated()) {
        const message = {
            page: "Forget",
            entered: req.query.entered,
            error: req.query.error,
            noEmail: req.query.noEmail,
            tokenExpired: req.query.tokenExpired
        }
        res.render("forget", message);
    }
    else res.redirect("/loggedIn");
});


app.get("/passwordReset", function (req, res) {
    if (!req.isAuthenticated()) {
        User.findOne({"_id": req.query.userID}, {"_id": 0, "token": 1}, function (err, result) {
            if (err) console.log(err);
            else {
                if (!result) res.redirect("/forget?tokenExpired=true");
                else {
                    if (result.token === req.query.token) {
                        const reset = {
                            error: req.query.error,
                            duplicatePwError: req.query.duplicatePwError,
                            userID: req.query.userID,
                            token: req.query.token
                        }
                        res.render("passwordReset", reset);
                    } else res.redirect("/forget?tokenExpired=true");
                }
            }
        });
    }
    else res.redirect("/loggedIn");
});


app.get("/change/:type", function (req, res) {
    const type = req.params.type;
    if (req.isAuthenticated()) {
        if (type === "displayname") {
            if (req.user.googleId === undefined) {
                const changeType = {
                    page: "Change",
                    error: req.query.error,
                    pwError: req.query.pwError,
                    duplicatePwError: req.query.duplicatePwError,
                    duplicateEmail: req.query.duplicateEmail,
                    duplicateDisplayname: req.query.duplicateDisplayname,
                    buttonValue: "changeDisplayname",
                    googleAcc: false
                }
                res.render("change", changeType);
            }
            else {
                const changeType = {
                    page: "Change",
                    error: req.query.error,
                    pwError: req.query.pwError,
                    duplicatePwError: req.query.duplicatePwError,
                    duplicateEmail: req.query.duplicateEmail,
                    duplicateDisplayname: req.query.duplicateDisplayname,
                    buttonValue: "changeDisplayname",
                    googleAcc: true
                }
                res.render("change", changeType);
            }
        }
        else if (type === "email") {
            if (req.user.googleId !== undefined) res.redirect("/account");
            else {
                const changeType = {
                    page: "Change",
                    error: req.query.error,
                    pwError: req.query.pwError,
                    duplicatePwError: req.query.duplicatePwError,
                    duplicateEmail: req.query.duplicateEmail,
                    duplicateDisplayname: req.query.duplicateDisplayname,
                    buttonValue: "changeEmail",
                    googleAcc: false
                }
                res.render("change", changeType);
            }
        }
        else if (type === "password") {
            if (req.user.googleId !== undefined) res.redirect("/account");
            else {
                const changeType = {
                    page: "Change",
                    error: req.query.error,
                    pwError: req.query.pwError,
                    duplicatePwError: req.query.duplicatePwError,
                    duplicateEmail: req.query.duplicateEmail,
                    duplicateDisplayname: req.query.duplicateDisplayname,
                    buttonValue: "changePassword",
                    googleAcc: false
                }
                res.render("change", changeType);
            }
        }
        else res.redirect("/account");
    }
    else res.redirect("/login");
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
        if (req.user.displayname === undefined) res.redirect("/change/displayname");
        else {
            const logged = {
                loggedIn: req.query.loggedIn,
                googleDisplayname: req.query.googleDisplayname
            }
            res.render("userHome", logged);
        }
    } else {
        res.redirect("/login");
    }
});


app.get("/userProfile", function (req, res) {
    if (req.isAuthenticated()) {
        const page = req.query.page;
        if (page === undefined) res.redirect("/userProfile?page=1");
        else {
            const albums = ((page - 1) * 10) + 1;
            Album.find({"position": {$gte: albums}}, null, {sort: {position: 1}}, function (err, results) {
                if (err) console.log(err);
                else {
                    Album.countDocuments({}, function (err, count) {
                        if (err) console.log(err);
                        else {
                            const listSize = count;
                            const pageLimit = (Math.trunc(count/10) + 1);
                            if ((count % 10) === 0 && count > 10 && page == pageLimit) res.redirect("/userProfile?page=" + (pageLimit - 1));
                            else if (page > pageLimit) res.redirect("/userProfile?page=" + pageLimit);
                            else if (page <= 0) res.redirect("/userProfile?page=1");
                            else {
                                setTimeout(function () {
                                    res.render("userProfile", {
                                        albumList: results,
                                        added: req.query.added,
                                        removed: req.query.removed,
                                        reordered: req.query.reordered,
                                        reorder: req.query.reorder,
                                        reorderError: req.query.reorderError,
                                        samePos: req.query.samePos,
                                        page: req.query.page,
                                        goto: req.query.goto,
                                        gotoError: req.query.gotoError,
                                        listSize: listSize,
                                        pages: pageLimit
                                    });
                                }, 500);
                            }
                        }
                    });
                }
            }).limit(10);
        }
    } else {
        res.redirect("/login");
    }
});


app.get("/albumSearch", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("albumSearch", {
            error: req.query.error,
            logged: true
        });
    } else {
        res.render("albumSearch", {
            error: req.query.error,
            logged: false
        });
    }
});


app.get("/album/:albumId", function (req, res) {
    const album = req.params.albumId;

    var artistName = "";
    var albumName = "";
    var yearRelease = "";
    var year = "";
    var albumArt = "";
    var videoTitle = new Array();
    var videoLink = new Array();
    var videoMap = new Map();
    var genreAlbum = new Array();
    var tracklist = new Array();

    db.getMaster(album, function(err, data) {
        if (err) console.log(err);
        else {
            if (data.artists !== undefined) {
                artistName = data.artists[0].name;
                albumName = data.title;
                yearRelease = data.year;
                albumArt = data.images[0].uri;
        
                if (data.year === 0 || undefined) {
                    yearRelease = "";
                    year = yearRelease;
                }
                else {
                    yearRelease = "(" + data.year + ")";
                    year = yearRelease.slice(1, yearRelease.length - 1);
                }

                if (data.videos !== undefined) {
                    for (i = 0; i < data.videos.length; i++) {
                        const artist = artistName + " - ";
                        const artistEnd = " - " + artistName;
                        const title = data.videos[i].title;
                        var vidTitle = "";
    
                        if (title.startsWith(artist) || title.startsWith(artistName + " – ") || title.startsWith(artist.toLowerCase()) || title.startsWith(artistName.toLowerCase() + " – ")) {
                            vidTitle = title.slice(artist.length, title.length);
                            videoTitle.push(vidTitle);
                            videoLink.push(data.videos[i].uri);
                        }
                        else if (title.endsWith(artistEnd) || title.endsWith(" – " + artistName) || title.endsWith(artistEnd.toLowerCase()) || title.endsWith(" – " + artistName.toLowerCase())) {
                            vidTitle = title.slice(0, title.length - artistEnd.length);
                            videoTitle.push(vidTitle);
                            videoLink.push(data.videos[i].uri);
                        }
                        else {
                            videoTitle.push(data.videos[i].title);
                            videoLink.push(data.videos[i].uri);
                        }
                    }
                    
                    var videoTitleLower = new Array();
                    var videoMapTemp = new Map();
    
                    for (k = 0; k < videoTitle.length; k++) {
                        videoTitleLower.push(videoTitle[k].toLowerCase());
                        videoMapTemp.set(videoTitleLower[k], videoLink[k]);
                    }
                    videoMap = new Map ([...videoMapTemp].sort((a, b) => String(a[0]).localeCompare(b[0])));
                }
        
                if (data.genres !== undefined) {
                    for (i = 0; i < data.genres.length; i++) genreAlbum.push(" " + data.genres[i]);
                }
                    
                if (data.styles !== undefined) {
                    for (i = 0; i < data.styles.length; i++) genreAlbum.push(" " + data.styles[i]);
                }
    
                if (data.tracklist !== undefined) {
                    var trackNumber = 0;
                    for (i = 0; i < data.tracklist.length; i++) {
                        if (data.tracklist[i].type_ != 'heading' && data.tracklist[i].position != 'Video') {
                            trackNumber++;
                            if (data.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + data.tracklist[i].title);
                            else tracklist.push(trackNumber + ". " + data.tracklist[i].title + " (" + data.tracklist[i].duration + ")");
                        }
                    }
                }
    
                if (req.isAuthenticated()) {
                    const addAlbum = req.body.add;
                    if (addAlbum === "added") {
                        Album.countDocuments({}, function (err, count) {
                            if (err) console.log(err);
                            else {
                                const albumAdd = new Album({
                                    albumID: album,
                                    title: artistName + " - " + albumName,
                                    year: yearRelease,
                                    img: albumArt,
                                    albumTracks: tracklist,
                                    position: count + 1
                                });
                                albumAdd.save();
                                setTimeout(function () {
                                    const page = Math.trunc(count/10);
                                    res.redirect("/userProfile?page=" + (page + 1) + "&added=true");
                                }, 1250);
                            }
                        });
                    }
                    else {
                        setTimeout(function () {
                            res.render("album", {
                                logged: true,
                                albumID: album,
                                artist: artistName,
                                title: albumName,
                                year: year,
                                cover: albumArt,
                                videoMap: videoMap,
                                genre: genreAlbum,
                                tracks: tracklist,
                                duplicate: req.query.duplicate
                            });
                        }, 500);
                    }
                }
                
                else {
                    setTimeout(function () {
                        res.render("album", {
                            logged: false,
                            albumID: album,
                            artist: artistName,
                            title: albumName,
                            year: year,
                            cover: albumArt,
                            videoMap: videoMap,
                            genre: genreAlbum,
                            tracks: tracklist,
                            duplicate: req.query.duplicate
                        });
                    }, 500);
                }
            }
        }
    });
});


app.post("/login", passport.authenticate("local", {successRedirect: "/userHome?loggedIn=true", failureRedirect: "/login?error=true"}));


app.post("/register", function (req, res) {
    if (req.body.username === "" || req.body.displayname === "" || req.body.passwordNew1 === "" || req.body.passwordNew2 === "") res.redirect("/register?error=true");
    else if (req.isAuthenticated()) res.redirect("/loggedIn");
    else {
        if (req.body.passwordNew1 !== req.body.passwordNew2) {
            res.redirect("/register?duplicatePwError=true");
        }

        else {
            User.countDocuments({"username": req.body.username}, function (err, count) {
                if (err) console.log(err);
                else if (count >= 1) res.redirect("/register?duplicateEmail=true");
                else {
                    User.countDocuments({"displayname": req.body.displayname}, function (err, count) {
                        if (err) console.log(err);
                        else if (count >= 1) res.redirect("/register?duplicateDisplayname=true");
                        else {
                            bcrypt.genSalt(10, function (err, salt) {
                                if (err) console.log(err);
                                else {
                                    bcrypt.hash(req.body.passwordNew2, salt, function (err, hash) {
                                        if (err) res.redirect("/register?duplicatePwError=true");
                                        else {
                                            const newUser = new User({
                                                username: req.body.username,
                                                password: hash,
                                                displayname: req.body.displayname,
                                            });
                                            newUser.save();
                                            res.redirect("/login?accCreated=true");
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    }
});


app.post("/forget", function (req, res) {
    if (req.body.username === "") res.redirect("/forget?error=true")
    else {
        User.countDocuments({username: req.body.username}, function (err, count) {
            if (err) console.log(err);
            else if (count < 1) res.redirect("/forget?noEmail=true");
            else {
                User.findOne({username: req.body.username}, {_id: 1}, function (err, id) {
                    if (err) console.log(err);
                    else {
                        var token = "";
                        crypto.randomBytes(20, function (err, bytes) {
                            if (err) console.log(err);
                            else {
                                token = bytes.toString('hex');
                                const expireTime = Date.now() + 600000;

                                User.updateOne({"_id": id}, {"token": token, "tokenExpire": expireTime, "awaitingReset": true}, function (err, result) {
                                    if (err) console.log(err);
                                    else {
                                        const email = {
                                            from: process.env.NODEMAILER_USER,
                                            to: req.body.username,
                                            subject: "Musica Password Recovery",
                                            //update this html field when posted online
                                            html: "<h2>Password Reset</h2><p>Click the link below to reset your Musica user password. If you did not request this, please ingore this email.</p><br><a href='http://localhost:3000/passwordReset?userID=" + id._id + "&token=" + token + "'>Musica Password Reset</a>" 
                                        };
                                        emailer.sendMail(email, function (err, info) {
                                            if (err) console.log(err);
                                        });
                                        res.redirect("/forget?entered=true");
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
    }
});


app.post("/passwordReset", function (req, res) {
    if (!req.isAuthenticated()) {
        const userID = req.query.userID;
        const token = req.query.token;
        if (req.body.passwordNew1 === "" || req.body.passwordNew2 === "") res.redirect("/passwordReset?userID=" + userID + "&token=" + token + "&error=true");
        else {
            if (req.body.passwordNew1 !== req.body.passwordNew2) res.redirect("/passwordReset?userID=" + userID + "&token=" + token + "&duplicatePwError=true");
            else {
                User.findOne({"_id": userID}, {token: token}, function (err, user) {
                    if (err) console.log(err);
                    else if (!user) res.redirect("/forget?tokenExpired=true");
                    else {
                        bcrypt.genSalt(10, function (err, salt) {
                            if (err) console.log(err);
                            else {
                                bcrypt.hash(req.body.passwordNew2, salt, function (err, hash) {
                                    if (err) console.log(err);
                                    else {
                                        User.updateOne({"_id": req.query.userID}, {$set: {password: hash}, 
                                                                $unset: {token: 1, tokenExpire: 1, awaitingReset: 1}}, function (err, result) {
                                            if (err) console.log(err);
                                            else res.redirect("/login?pwReset=true");
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        }
    }
    else res.redirect("/loggedIn");
});


app.post("/change/:type", function (req, res) {
    if (req.isAuthenticated()) {
        const type = req.params.type;
        if (type === "displayname") {
            if (req.user.googleId === undefined) {
                if (req.body.displayname === "" || req.body.password === "") res.redirect("/change/displayname?error=true");
                else {
                    User.countDocuments({"displayname": req.body.displayname}, function (err, count) {
                        if (err) console.log(err);
                        else if (count >= 1) res.redirect("/change/displayname?duplicateDisplayname=true");
                        else {
                            User.findOne({"_id": req.user._id}, function (err, user) {
                                if (err) console.log(err);
                                else {
                                    bcrypt.compare(req.body.password, user.password, function (err, result) {
                                        if (err) res.redirect("/change/displayname?pwError=true");
                                        else if (result === false) res.redirect("/change/displayname?pwError=true");
                                        else {
                                            if (req.body.displayname === "") res.redirect("/change/displayname?error=true");
                                            User.updateOne({"_id": req.user._id}, {$set: {displayname: req.body.displayname}}, function (err, result) {
                                                if (err) console.log(err);
                                                else res.redirect("/account?displaynameUpdate=true");
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            }
            else {
                if (req.body.displayname === "") res.redirect("/change/displayname?error=true");
                else {
                    User.countDocuments({"displayname": req.body.displayname}, function (err, count) {
                        if (err) console.log(err);
                        else if (count >= 1) res.redirect("/change/displayname?duplicateDisplayname=true");
                        else {
                            User.updateOne({"_id": req.user._id}, {$set: {displayname: req.body.displayname}}, function (err, result) {
                                if (err) console.log(err);
                                else res.redirect("/userHome?googleDisplayname=true");
                            });
                        }
                    });
                }
            }
        }

        else if (type === "email") {
            if (req.user.googleId !== undefined) res.redirect("/account");
            if (req.body.email === "" || req.body.password === "") res.redirect("/change/email?error=true");
            else {
                User.countDocuments({"username": req.body.email}, function (err, count) {
                    if (err) console.log(err);
                    else if (count >= 1) res.redirect("/change/email?duplicateEmail=true");
                    else {
                        User.findOne({"_id": req.user._id}, function (err, user) {
                            if (err) console.log(err);
                            else {
                                bcrypt.compare(req.body.password, user.password, function (err, result) {
                                    if (err) res.redirect("/change/email?pwError=true");
                                    else if (result === false) res.redirect("/change/email?pwError=true");
                                    else {
                                        User.updateOne({"_id": req.user._id}, {$set: {username: req.body.email}}, function (err, result) {
                                            if (err) console.log(err);
                                            else res.redirect("/account?emailUpdate=true");
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        }

        else if (type === "password") {
            if (req.user.googleId !== undefined) res.redirect("/account");
            if (req.body.password === "" || req.body.passwordNew1 === "" || req.body.passwordNew2 === "") res.redirect("/change/password?error=true");
            else {
                User.findOne({"_id": req.user._id}, function (err, user) {
                    if (err) console.log(err);
                    else {
                        bcrypt.compare(req.body.password, user.password, function (err, result) {
                            if (err) res.redirect("/change/password?pwError=true");
                            else if (result === false) res.redirect("/change/password?pwError=true");
                            else if (req.body.passwordNew1 !== req.body.passwordNew2) res.redirect("/change/password?duplicatePwError=true");
                            else {
                                bcrypt.genSalt(10, function (err, salt) {
                                    if (err) console.log(err);
                                    else {
                                        bcrypt.hash(req.body.passwordNew2, salt, function (err, hash) {
                                            if (err) res.redirect("/change/password?duplicatePwError=true");
                                            else {
                                                User.updateOne({"_id": req.user._id}, {$set: {password: hash}}, function (err, result) {
                                                    if (err) console.log(err);
                                                    else res.redirect("/account?passwordUpdate=true");
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        }
    }
    else res.redirect("/login");
});


app.post("/userProfile", function (req, res) {
    if (req.isAuthenticated()) {
        const end = req.body.end;
        const goto = req.body.goto;
        const albumRemove = req.body.remove;
        const reorderedAlbum = req.body.reordered;
        
        if (end === "end") {
            Album.countDocuments({}, function (err, count) {
                if (err) console.log(err);
                else {
                    const finalPage = (Math.trunc(count/10) + 1);
                    if ((count % 10) === 0 && count > 10) res.redirect("/userProfile?page=" + (finalPage - 1));
                    else res.redirect("/userProfile?page=" + finalPage);
                }
            });
        }

        else if (goto === "goto") {
            const gotoPage = parseInt(req.body.gotoPage);
            Album.findOne({albumID: albumRemove}, {position: 1}, function (err, albumPos) {
                if (err) console.log(err);
                else {
                    Album.countDocuments({}, function (err, count) {
                        if (err) console.log(err);
                        else {
                            const pageLimit = (Math.trunc(count/10) + 1);
                            const page = (Math.trunc(albumPos/10) + 1);
                            if (gotoPage <= 0 || isNaN(gotoPage) || gotoPage > pageLimit) res.redirect("/userProfile?page=" + page + "&goto=true&gotoError=true");
                            else res.redirect("/userProfile?page=" + gotoPage);
                        }
                    });
                }
            });
        }

        else if (albumRemove !== undefined) {
            Album.findOne({albumID: albumRemove}, {position: 1}, function (err, albumPos) {
                if (err) console.log(err);
                else {
                    Album.updateMany({"position": {$gt: albumPos.position}}, {$inc: {position: -1}}, function (err, result) {
                        if (err) console.log(err);
                        else {
                            Album.deleteOne({albumID: albumRemove}, function (err, result) {
                                if (err) console.log(err);
                                else {
                                    var page = (Math.trunc(albumPos.position/10) + 1);
                                    if (albumPos.position % 10 === 0) page--;
                                    Album.countDocuments({}, function (err, count) {
                                        if (err) console.log(err);
                                        else {
                                            setTimeout(function () {
                                                if ((count % 10) === 0 && count > 10) res.redirect("/userProfile?page=" + (page - 1) + "&reorder=true&removed=true");
                                                else res.redirect("userProfile?page=" + page + "&reorder=true&removed=true");
                                            }, 1250);
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
        
        else {
            const newPos = parseInt(req.body.newPos);
            Album.find({albumID: reorderedAlbum}, {albumID: 1, position: 1}, function (err, id) {
                if (err) {
                    console.log(err);
                    res.redirect("/userProfile?page=1");
                }
                else {
                    var page = (Math.trunc(id[0].position/10) + 1);
                    if ((id[0].position % 10) === 0) page--;
                    if (id !== undefined) {
                        const currentPos = id[0].position;
                        const currentId = id[0].albumID;

                        Album.countDocuments({}, function (err, count) {
                            if (err) console.log(err);
                            else {
                                if (newPos <= 0 || isNaN(newPos) || newPos > count) res.redirect("/userProfile?page=" + page + "&reorder=true&reorderError=true");
                                else if (newPos === currentPos) res.redirect("/userProfile?page=" + page + "&reorder=true&samePos=true");
                                else {
                                    if (newPos > currentPos) {
                                        var newPositionArray = new Array();
                                        for (i = currentPos; i <= newPos; i++) {
                                            newPositionArray.push(i);
                                        }
                                        async.eachSeries(newPositionArray, async function (pos, done) {
                                            const shiftUp = await Album.updateOne({"position": pos}, {$set: {position: pos - 1}}, done);
                                            if (pos === newPos) {
                                                newPositionArray = [];
                                                const final = await Album.updateOne({"albumID": currentId}, {$set: {position: newPos}});
                                                return final;
                                            }
                                            else return shiftUp;
                                        });
                                    }
                                    else {
                                        var newPositionArray = new Array();
                                        for (i = currentPos; i >= newPos; i--) {
                                            newPositionArray.push(i);
                                        }
                                        async.eachSeries(newPositionArray, async function (pos, done) {
                                            const shiftDown = await Album.updateOne({"position": pos}, {$set: {position: pos + 1}}, done);
                                            if (pos === newPos) {
                                                newPositionArray = [];
                                                const final = await Album.updateOne({"albumID": currentId}, {$set: {position: newPos}});
                                                return final;
                                            }
                                            else return shiftDown;
                                        });
                                    }
                                    setTimeout(function () {
                                        page = (Math.trunc(newPos/10) + 1);
                                        if ((newPos % 10) === 0) page--;
                                        res.redirect("/userProfile?page=" + page + "&reordered=true&reorder=true");
                                    }, 1250);
                                }
                            }
                        });
                    }
                    else res.redirect("/userProfile?page=" + page + "&reorder=true&reorderError=true");
                }
            });
        }
    }
    else res.redirect("/login");
});


app.post("/albumSearch", function (req, res) {
    const artistName = req.body.userArtist;
    const albumName = req.body.userAlbum;
    const albumYear = req.body.year;
    var discogsId = req.body.discogsId;

    if (artistName === "" && albumName === "" && albumYear === "" && discogsId === "") res.redirect("albumSearch?error=true");

    else {
        if (discogsId !== "") {
            discogsId = parseInt(discogsId);
            db.search({master_id: discogsId}).then(function (searchResult) {
                if (searchResult.results.length > 0) {
                    setTimeout(function () {
                        res.redirect("album/" + searchResult.results[0].master_id);
                    }, 1000);
                }
                else res.redirect("albumSearch?error=true");
            });
        }

        else {
            db.search({artist: artistName, release_title: albumName, year: albumYear, type: "master"}).then(function (searchResult) {
                var albumID1 = 99999999999999;
                var albumID2 = 99999999999999;
                if (searchResult.results.length > 0) {
                    var i = searchResult.results.findIndex(album => album.country === "US");
                    while (i >= 0 && i < searchResult.results.length - 1) {
                        const albumID1temp = searchResult.results[i].master_id;
                        if (albumID1temp < albumID1 && searchResult.results[i].country === "US") {
                            albumID1 = albumID1temp;
                        }
                        i++;
                    }
    
                    var j = searchResult.results.findIndex(album => album.country === "UK");
                    while (j >= 0 && j < searchResult.results.length - 1) {
                        const albumID2temp = searchResult.results[j].master_id;
                        if (albumID2temp < albumID2 && searchResult.results[j].country === "UK") {
                            albumID2 = albumID2temp;
                        } 
                        j++;
                    }
    
                    if (albumID1 < albumID2) {
                        setTimeout(function () {
                            res.redirect("album/" + albumID1);
                        }, 1000);
                    } else if (albumID1 > albumID2) {
                        setTimeout(function () {
                            res.redirect("album/" + albumID2);
                        }, 1000);
                    } else {
                        albumID1 = searchResult.results[0].master_id;
                        setTimeout(function () {
                            res.redirect("album/" + albumID1);
                        }, 1000);
                    }
                }
                else {
                    res.redirect("albumSearch?error=true");
                }
            });
        }
    }
});


app.post("/album/:albumId", function (req, res) {
    const album = req.params.albumId;
    Album.countDocuments({albumID: album}, function (err, result) {
        if (err) console.log(err);
        else if (result > 0) res.redirect("/album/" + album + "?duplicate=true");
        else {
            var artistName = "";
            var albumName = "";
            var yearRelease = "";
            var year = "";
            var albumArt = "";
            var videoTitle = new Array();
            var videoLink = new Array();
            var videoMap = new Map();
            var genreAlbum = new Array();
            var tracklist = new Array();

            db.getMaster(album, function(err, data) {
                if (data.artists !== undefined) {
                    artistName = data.artists[0].name;
                    albumName = data.title;
                    yearRelease = data.year;
                    albumArt = data.images[0].uri;

                    if (data.year === 0 || undefined) {
                        yearRelease = "";
                        year = yearRelease;
                    }
                    else {
                        yearRelease = "(" + data.year + ")";
                        year = yearRelease.slice(1, yearRelease.length - 1);
                    }

                    if (data.videos !== undefined) {
                        for (i = 0; i < data.videos.length; i++) {
                            const artist = artistName + " - ";
                            const artistEnd = " - " + artistName;
                            const title = data.videos[i].title;
                            var vidTitle = "";

                            if (title.startsWith(artist) || title.startsWith(artistName + " – ") || title.startsWith(artist.toLowerCase()) || title.startsWith(artistName.toLowerCase() + " – ")) {
                                vidTitle = title.slice(artist.length, title.length);
                                videoTitle.push(vidTitle);
                                videoLink.push(data.videos[i].uri);
                            }
                            else if (title.endsWith(artistEnd) || title.endsWith(" – " + artistName) || title.endsWith(artistEnd.toLowerCase()) || title.endsWith(" – " + artistName.toLowerCase())) {
                                vidTitle = title.slice(0, title.length - artistEnd.length);
                                videoTitle.push(vidTitle);
                                videoLink.push(data.videos[i].uri);
                            }
                            else {
                                videoTitle.push(data.videos[i].title);
                                videoLink.push(data.videos[i].uri);
                            }
                        }

                        var videoTitleLower = new Array();
                        var videoMapTemp = new Map();

                        for (k = 0; k < videoTitle.length; k++) {
                            videoTitleLower.push(videoTitle[k].toLowerCase());
                            videoMapTemp.set(videoTitleLower[k], videoLink[k]);
                        }
                        videoMap = new Map ([...videoMapTemp].sort((a, b) => String(a[0]).localeCompare(b[0])));
                    }

                    if (data.genres !== undefined) {
                        for (i = 0; i < data.genres.length; i++) genreAlbum.push(" " + data.genres[i]);
                    }
                        
                    if (data.styles !== undefined) {
                        for (i = 0; i < data.styles.length; i++) genreAlbum.push(" " + data.styles[i]);
                    }

                    if (data.tracklist !== undefined) {
                        var trackNumber = 0;
                        for (i = 0; i < data.tracklist.length; i++) {
                            if (data.tracklist[i].type_ != 'heading' && data.tracklist[i].position != 'Video') {
                                trackNumber++;
                                if (data.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + data.tracklist[i].title);
                                else tracklist.push(trackNumber + ". " + data.tracklist[i].title + " (" + data.tracklist[i].duration + ")");
                            }
                        }
                    }

                    if (req.isAuthenticated()) {
                        const addAlbum = req.body.add;
                        if (addAlbum === "added") {
                            Album.countDocuments({}, function (err, count) {
                                if (err) console.log(err);
                                else {
                                    const albumAdd = new Album({
                                        albumID: album,
                                        title: artistName + " - " + albumName,
                                        year: yearRelease,
                                        img: albumArt,
                                        albumTracks: tracklist,
                                        position: count + 1
                                    });
                                    albumAdd.save();
                                    setTimeout(function () {
                                        const page = Math.trunc(count/10);
                                        res.redirect("/userProfile?page=" + (page + 1) + "&added=true");
                                    }, 1250);
                                }
                            });
                        }
                        else {
                            setTimeout(function () {
                                res.render("album", {
                                    logged: true,
                                    albumID: album,
                                    artist: artistName,
                                    title: albumName,
                                    year: year,
                                    cover: albumArt,
                                    videoMap: videoMap,
                                    genre: genreAlbum,
                                    tracks: tracklist
                                });
                            }, 500);
                        }
                    }
                    
                    else {
                        setTimeout(function () {
                            res.render("album", {
                                logged: false,
                                albumID: album,
                                artist: artistName,
                                title: albumName,
                                year: year,
                                cover: albumArt,
                                videoMap: videoMap,
                                genre: genreAlbum,
                                tracks: tracklist
                            });
                        }, 500);
                    }
                }
            });
        }
    });
});


app.listen(3000, function () {
    console.log("Server started!");
    setInterval(function() {
        User.find({awaitingReset: true}, function (err, user) {
            if (err) console.log(err);
            else {
                for (i = 0; i < user.length; i++) {
                    var expired = new Date(user[i].tokenExpire).getTime() <= Date.now();
                    if (expired) {
                        User.updateOne({"_id": user[i]._id}, {$unset: {token: 1, tokenExpire: 1, awaitingReset: 1}}, function (err, result) {
                            if (err) console.log(err);
                        });
                    }
                }
            }
        });
    }, 600000);
});