require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
var async = require("async");
const crypto = require("crypto");
const validator = require("validator");
const swearFilter = require("swearfilter");
const helmet = require("helmet");
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

const filter = new swearFilter({
    smartDetect: true,
    baseFilter: {
        useBaseFilter: true,
    }
});

const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            imgSrc: ["'self'", 'i.discogs.com']
        }
    })
);
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false
    }
}));
app.use(passport.initialize());
app.use(passport.authenticate("session"));

const mongoose = require("mongoose");
const mongodb = require("mongodb").MongoClient;
const { Db } = require("mongodb");
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
            var loggedIn = req.query.loggedIn;
            var googleDisplayname = req.query.googleDisplayname;

            if (loggedIn !== undefined) loggedIn = validator.escape(loggedIn);
            if (googleDisplayname !== undefined) googleDisplayname = validator.escape(googleDisplayname);

            const logged = {
                loggedIn: loggedIn,
                googleDisplayname: googleDisplayname,
                list: req.user.displayname
            }
            res.render("userHome", logged);
        }
    } else res.render("home", {loggedOut: false});
});


app.get("/login", function (req, res) {
    if (req.isAuthenticated()) res.render("loggedIn");
    else {
        var error = req.query.error;
        var accCreated = req.query.accCreated;
        var pwReset = req.query.pwReset;

        if (error !== undefined) error = validator.escape(error);
        if (accCreated !== undefined) accCreated = validator.escape(accCreated);
        if (pwReset !== undefined) pwReset = validator.escape(pwReset);

        const errCheck = {
            page: "Login",
            error: error,
            accCreated: accCreated,
            pwReset: pwReset
        };
        res.render("login", errCheck);
    }
});


app.get("/register", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("loggedIn");
    } else {
        var error = req.query.error;
        var duplicatePwError = req.query.duplicatePwError;
        var duplicateEmail = req.query.duplicateEmail;
        var duplicateDisplayname = req.query.duplicateDisplayname;
        var displaynameError = req.query.displaynameError;
        var displaynameSwear = req.query.displaynameSwear;

        if (error !== undefined) error = validator.escape(error);
        if (duplicatePwError !== undefined) duplicatePwError = validator.escape(duplicatePwError);
        if (duplicateEmail !== undefined) duplicateEmail = validator.escape(duplicateEmail);
        if (duplicateDisplayname !== undefined) duplicateDisplayname = validator.escape(duplicateDisplayname);
        if (displaynameError !== undefined) displaynameError = validator.escape(displaynameError);
        if (displaynameSwear !== undefined) displaynameSwear = validator.escape(displaynameSwear);

        const errCheck = {
            page: "Register",
            error: error,
            duplicatePwError: duplicatePwError,
            duplicateEmail: duplicateEmail,
            duplicateDisplayname: duplicateDisplayname,
            displaynameError: displaynameError,
            displaynameSwear: displaynameSwear
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
        var displaynameUpdate = req.query.displaynameUpdate;
        var emailUpdate = req.query.emailUpdate;
        var passwordUpdate = req.query.passwordUpdate;

        if (displaynameUpdate !== undefined) displaynameUpdate = validator.escape(displaynameUpdate);
        if (emailUpdate !== undefined) emailUpdate = validator.escape(emailUpdate);
        if (passwordUpdate !== undefined) passwordUpdate = validator.escape(passwordUpdate);

        if (req.user.googleId === undefined) {
            const message = {
                displaynameUpdate: displaynameUpdate,
                emailUpdate: emailUpdate,
                passwordUpdate: passwordUpdate,
                googleAcc: false,
                list: req.user.displayname
            }
            res.render("account", message);
        }
        else if (req.user.googleId !== undefined) {
            const message = {
                displaynameUpdate: displaynameUpdate,
                emailUpdate: emailUpdate,
                passwordUpdate: passwordUpdate,
                googleAcc: true,
                list: req.user.displayname
            }
            res.render("account", message);
        } else res.redirect("/account");
    }
    else res.redirect("/login");
});


app.get("/forget", function (req, res) {
    if (!req.isAuthenticated()) {
        var entered = req.query.entered;
        var error = req.query.error;
        var noEmail = req.query.noEmail;
        var tokenExpired = req.query.tokenExpired;

        if (entered !== undefined) entered = validator.escape(entered);
        if (error !== undefined) error = validator.escape(error);
        if (noEmail !== undefined) noEmail = validator.escape(noEmail);
        if (tokenExpired !== undefined) tokenExpired = validator.escape(tokenExpired);

        const message = {
            page: "Forget",
            entered: entered,
            error: error,
            noEmail: noEmail,
            tokenExpired: tokenExpired
        }
        res.render("forget", message);
    }
    else res.redirect("/loggedIn");
});


app.get("/passwordReset", function (req, res) {
    if (!req.isAuthenticated()) {
        var userID = req.query.userID;
        if (userID !== undefined) userID = validator.escape(userID);

        User.findOne({"_id": userID}, {"_id": 0, "token": 1}, function (err, result) {
            if (err) console.log(err);
            else {
                if (!result) res.redirect("/forget?tokenExpired=true");
                else {
                    var token = req.query.token;
                    if (token !== undefined) token = validator.escape(token);

                    if (result.token === token) {
                        var error = req.query.error;
                        var duplicatePwError = req.query.duplicatePwError;
                        if (error !== undefined) error = validator.escape(error);
                        if (duplicatePwError !== undefined) duplicatePwError = validator.escape(duplicatePwError);

                        const reset = {
                            error: error,
                            duplicatePwError: duplicatePwError,
                            userID: userID,
                            token: token
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
    const type = validator.escape(req.params.type);
    if (req.isAuthenticated()) {
        var error = req.query.error;
        var pwError = req.query.pwError;
        var duplicatePwError = req.query.duplicatePwError;
        var duplicateEmail = req.query.duplicateEmail;
        var duplicateDisplayname = req.query.duplicateDisplayname;
        var displaynameError = req.query.displaynameError;
        var displaynameSwear = req.query.displaynameSwear;

        if (error !== undefined) error = validator.escape(error);
        if (pwError !== undefined) pwError = validator.escape(pwError);
        if (duplicatePwError !== undefined) duplicatePwError = validator.escape(duplicatePwError);
        if (duplicateEmail !== undefined) duplicateEmail = validator.escape(duplicateEmail);
        if (duplicateDisplayname !== undefined) duplicateDisplayname = validator.escape(duplicateDisplayname);
        if (displaynameError !== undefined) displaynameError = validator.escape(displaynameError);
        if (displaynameSwear !== undefined) displaynameSwear = validator.escape(displaynameSwear);

        if (type === "displayname") {
            if (req.user.googleId === undefined) {
                const changeType = {
                    page: "Change",
                    error: error,
                    pwError: pwError,
                    duplicatePwError: duplicatePwError,
                    duplicateEmail: duplicateEmail,
                    duplicateDisplayname: duplicateDisplayname,
                    displaynameError: displaynameError,
                    displaynameSwear: displaynameSwear,
                    buttonValue: "changeDisplayname",
                    googleAcc: false
                }
                res.render("change", changeType);
            }
            else {
                const changeType = {
                    page: "Change",
                    error: error,
                    pwError: pwError,
                    duplicatePwError: duplicatePwError,
                    duplicateEmail: duplicateEmail,
                    duplicateDisplayname: duplicateDisplayname,
                    displaynameError: displaynameError,
                    displaynameSwear: displaynameSwear,
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
                    error: error,
                    pwError: pwError,
                    duplicatePwError: duplicatePwError,
                    duplicateEmail: duplicateEmail,
                    duplicateDisplayname: duplicateDisplayname,
                    displaynameError: displaynameError,
                    displaynameSwear: displaynameSwear,
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
                    error: error,
                    pwError: pwError,
                    duplicatePwError: duplicatePwError,
                    duplicateEmail: duplicateEmail,
                    duplicateDisplayname: duplicateDisplayname,
                    displaynameError: displaynameError,
                    displaynameSwear: displaynameSwear,
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
            var displayName = req.params.displayName;
            if (displayName !== undefined) displayName = validator.escape(displayName);

            var loggedIn = req.query.loggedIn;
            var googleDisplayname = req.query.googleDisplayname;

            if (loggedIn !== undefined) loggedIn = validator.escape(loggedIn);
            if (googleDisplayname !== undefined) googleDisplayname = validator.escape(googleDisplayname);

            const logged = {
                loggedIn: loggedIn,
                googleDisplayname: googleDisplayname,
                list: req.user.displayname
            }
            res.render("userHome", logged);
        }
    } else {
        res.redirect("/");
    }
});


app.get("/userProfile", function (req, res) {
    res.render("userNoProfile");
});


app.get("/userProfile/:displayName", function (req, res) {
    var displayName = req.params.displayName;
    if (displayName !== undefined || displayName === "") displayName = validator.escape(displayName);
    else res.redirect("/userProfile");
    User.findOne({displayname: displayName}, function (err, userId) {
        if (err) console.log(err);
        else if (!userId) res.redirect("/");
        else {
            const userID = userId._id;
            var page = req.query.page;
            if (page !== undefined) page = validator.escape(page);

            const regex = /^[0-9]+$/;
            const validPage = regex.test(page);
            if (page === undefined || validPage === false) res.redirect("/userProfile/" + displayName + "?page=1");

            else {
                const albums = ((page - 1) * 10) + 1;
                Album.find({"position": {$gte: albums}, "userID": userID}, null, {sort: {position: 1}}, function (err, results) {
                    if (err) console.log(err);
                    else {
                        Album.countDocuments({"userID": userID}, function (err, count) {
                            if (err) console.log(err);
                            else {
                                const listSize = count;
                                const pageLimit = (Math.trunc(count/10) + 1);
                                if ((count % 10) === 0 && count >= 10 && page == pageLimit) res.redirect("/userProfile/" + displayName + "?page=" + (pageLimit - 1));
                                else if (page > pageLimit) res.redirect("/userProfile/" + displayName + "?page=" + pageLimit);
                                else if (page <= 0) res.redirect("/userProfile/" + displayName + "?page=1");
                                else {
                                    var added = req.query.added;
                                    var removed = req.query.removed;
                                    var reordered = req.query.reordered;
                                    var reorder = req.query.reorder;
                                    var reorderError = req.query.reorderError;
                                    var samePos = req.query.samePos;
                                    var goto = req.query.goto;
                                    var gotoError = req.query.gotoError;

                                    if (added !== undefined) added = validator.escape(added);
                                    if (removed !== undefined) removed = validator.escape(removed);
                                    if (reordered !== undefined) reordered = validator.escape(reordered);
                                    if (reorder !== undefined) reorder = validator.escape(reorder);
                                    if (reorderError !== undefined) reorderError = validator.escape(reorderError);
                                    if (samePos !== undefined) samePos = validator.escape(samePos);
                                    if (goto !== undefined) goto = validator.escape(goto);
                                    if (gotoError !== undefined) gotoError = validator.escape(gotoError);

                                    var logged = false;
                                    if (req.user) {
                                        if (userId.displayname === req.user.displayname) logged = true;
                                        else logged = false;
                                    }
                                    
                                    if (req.user) {
                                        setTimeout(function () {
                                            res.render("userProfile", {
                                                albumList: results,
                                                added: added,
                                                removed: removed,
                                                reordered: reordered,
                                                reorder: reorder,
                                                reorderError: reorderError,
                                                samePos: samePos,
                                                page: page,
                                                goto: goto,
                                                gotoError: gotoError,
                                                listSize: listSize,
                                                pages: pageLimit,
                                                list: displayName,
                                                logged: logged,
                                                loggedToolbar: true
                                            });
                                        }, 500);
                                    }
                                    else {
                                        setTimeout(function () {
                                            res.render("userProfile", {
                                                albumList: results,
                                                added: added,
                                                removed: removed,
                                                reordered: reordered,
                                                reorder: reorder,
                                                reorderError: reorderError,
                                                samePos: samePos,
                                                page: page,
                                                goto: goto,
                                                gotoError: gotoError,
                                                listSize: listSize,
                                                pages: pageLimit,
                                                list: displayName,
                                                logged: logged,
                                                loggedToolbar: false
                                            });
                                        }, 500);
                                    }
                                }
                            }
                        });
                    }
                }).limit(10);
            }
        }
    });
});


app.get("/albumSearch", function (req, res) {
    var notFound = req.query.notFound;
    var error = req.query.error;
    var discogsSearch = req.query.discogsSearch;
    if (notFound !== undefined) notFound = validator.escape(notFound);
    if (error !== undefined) error = validator.escape(error);
    if (discogsSearch !== undefined) discogsSearch = validator.escape(discogsSearch);

    if (req.isAuthenticated()) {
        res.render("albumSearch", {
            notFound: notFound,
            error: error,
            discogsSearch: discogsSearch,
            logged: true,
            list: req.user.displayname
        });
    } else {
        res.render("albumSearch", {
            notFound: notFound,
            error: error,
            discogsSearch: discogsSearch,
            logged: false,
            list: ""
        });
    }
});


app.get("/album/:albumId", function (req, res) {
    var album = req.params.albumId;
    if (album !== undefined) album = validator.escape(album);

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
        if (err) {
            console.log(err);
            res.redirect("/albumSearch?notFound=true");
        }

        else {
            if (data.artists !== undefined) {
                artistName = data.artists[0].name;
                albumName = data.title;
                yearRelease = data.year;

                const censoredAlbums = require("./scripts/censoredAlbums");
                if (censoredAlbums.includes(parseInt(album))) albumArt = "/censored.png";
                else if (album == "24535" && data.images[5].uri !== undefined) albumArt = data.images[5].uri; //special case
                else if (data.images[0].uri !== undefined) albumArt = data.images[0].uri;
        
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
                    if (data.genres.includes("Death Metal", "Goregrind", "Pornogrind")) albumArt = "/censored.png";
                }
                    
                if (data.styles !== undefined) {
                    for (i = 0; i < data.styles.length; i++) genreAlbum.push(" " + data.styles[i]);
                    if (data.styles.includes("Death Metal", "Goregrind", "Pornogrind")) albumArt = "/censored.png";
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
                    var addAlbum = req.body.add;
                    if (addAlbum !== undefined) addAlbum = validator.escape(addAlbum);

                    if (addAlbum === "added") {
                        Album.countDocuments({"userID": req.user._id}, function (err, count) {
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
                                    res.redirect("/userProfile/" + req.user.displayname + "?page=" + (page + 1) + "&added=true");
                                }, 1250);
                            }
                        });
                    }
                    else {
                        var duplicate = req.query.duplicate;
                        if (duplicate !== undefined) duplicate = validator.escape(duplicate);

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
                                duplicate: duplicate,
                                list: req.user.displayname
                            });
                        }, 500);
                    }
                }
                
                else {
                    var duplicate = req.query.duplicate;
                    if (duplicate !== undefined) duplicate = validator.escape(duplicate);

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
                            duplicate: duplicate
                        });
                    }, 500);
                }
            }
            else res.redirect("albumSearch");
        }
    });
});



app.post("/login", passport.authenticate("local", {successRedirect: "/userHome?loggedIn=true", failureRedirect: "/login?error=true"}));


app.post("/register", function (req, res) {
    var username = req.body.username;
    var displayname = req.body.displayname;
    var passwordNew1 = req.body.passwordNew1;
    var passwordNew2 = req.body.passwordNew2;

    if (username !== undefined) username = validator.escape(username);
    if (displayname !== undefined) displayname = validator.escape(displayname);
    if (passwordNew1 !== undefined) passwordNew1 = validator.escape(passwordNew1);
    if (passwordNew2 !== undefined) passwordNew2 = validator.escape(passwordNew2);

    if (username === "" || displayname === "" || passwordNew1 === "" || passwordNew2 === "") res.redirect("/register?error=true");
    else if (req.isAuthenticated()) res.redirect("/loggedIn");
    else {
        if (passwordNew1 !== passwordNew2) {
            res.redirect("/register?duplicatePwError=true");
        }
        else {
            const regex = /^[a-zA-Z0-9]+$/;
            const validName = regex.test(displayname);
            User.countDocuments({"username": username}, function (err, count) {
                if (err) console.log(err);
                else if (count >= 1) res.redirect("/register?duplicateEmail=true");
                else {
                    displayname = filter.censor(displayname);
                    User.countDocuments({"displayname": displayname}, function (err, count) {
                        if (err) console.log(err);
                        else if (count >= 1) res.redirect("/register?duplicateDisplayname=true");
                        else if (displayname.includes("*") || displayname.length > 20) res.redirect("/register?displaynameSwear=true");
                        else if (validName === false || displayname.length > 20) res.redirect("/register?displaynameError=true");
                        else {
                            bcrypt.genSalt(10, function (err, salt) {
                                if (err) console.log(err);
                                else {
                                    bcrypt.hash(passwordNew2, salt, function (err, hash) {
                                        if (err) res.redirect("/register?duplicatePwError=true");
                                        else {
                                            const newUser = new User({
                                                username: username,
                                                password: hash,
                                                displayname: displayname,
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
    var username = req.body.username;
    if (username !== undefined) username = validator.escape(username);

    if (username === "") res.redirect("/forget?error=true")
    else {
        User.countDocuments({username: username}, function (err, count) {
            if (err) console.log(err);
            else if (count < 1) res.redirect("/forget?noEmail=true");
            else {
                User.findOne({username: username}, {_id: 1}, function (err, id) {
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
                                            to: username,
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
        const userID = validator.escape(req.query.userID);
        const token = validator.escape(req.query.token);
        var passwordNew1 = req.body.passwordNew1;
        var passwordNew2 = req.body.passwordNew2;

        if (passwordNew1 !== undefined) passwordNew1 = validator.escape(passwordNew1);
        if (passwordNew2 !== undefined) passwordNew2 = validator.escape(passwordNew2);

        if (passwordNew1 === "" || passwordNew2 === "") res.redirect("/passwordReset?userID=" + userID + "&token=" + token + "&error=true");
        else {
            if (passwordNew1 !== passwordNew2) res.redirect("/passwordReset?userID=" + userID + "&token=" + token + "&duplicatePwError=true");
            else {
                User.findOne({"_id": userID}, {token: token}, function (err, user) {
                    if (err) console.log(err);
                    else if (!user) res.redirect("/forget?tokenExpired=true");
                    else {
                        bcrypt.genSalt(10, function (err, salt) {
                            if (err) console.log(err);
                            else {
                                bcrypt.hash(passwordNew2, salt, function (err, hash) {
                                    if (err) console.log(err);
                                    else {
                                        User.updateOne({"_id": userID}, {$set: {password: hash}, 
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
        var type = validator.escape(req.params.type);
        var displayname = req.body.displayname;
        var email = req.body.email;
        var password = req.body.password;
        var passwordNew1 = req.body.passwordNew1;
        var passwordNew2 = req.body.passwordNew2;

        if (displayname !== undefined) displayname = validator.escape(displayname);
        if (email !== undefined) email = validator.escape(email);
        if (password !== undefined) password = validator.escape(password);
        if (passwordNew1 !== undefined) passwordNew1 = validator.escape(passwordNew1);
        if (passwordNew2 !== undefined) passwordNew2 = validator.escape(passwordNew2);

        if (type === "displayname") {
            const regex = /^[a-zA-Z0-9]+$/;
            const validName = regex.test(displayname);
            if (req.user.googleId === undefined) {
                if (displayname === "" || password === "") res.redirect("/change/displayname?error=true");
                else {
                    displayname = filter.censor(displayname);
                    User.countDocuments({"displayname": displayname}, function (err, count) {
                        if (err) console.log(err);
                        else if (count >= 1) res.redirect("/change/displayname?duplicateDisplayname=true");
                        else if (displayname.includes("*") || displayname.length > 20) res.redirect("/change/displayname?displaynameSwear=true");
                        else if (validName === false || displayname.length > 20) res.redirect("/change/displayname?displaynameError=true");
                        else {
                            User.findOne({"_id": req.user._id}, function (err, user) {
                                if (err) console.log(err);
                                else {
                                    bcrypt.compare(password, user.password, function (err, result) {
                                        if (err) res.redirect("/change/displayname?pwError=true");
                                        else if (result === false) res.redirect("/change/displayname?pwError=true");
                                        else {
                                            if (displayname === "") res.redirect("/change/displayname?error=true");
                                            User.updateOne({"_id": req.user._id}, {$set: {displayname: displayname}}, function (err, result) {
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
                if (displayname === "") res.redirect("/change/displayname?error=true");
                else {
                    displayname = filter.censor(displayname);
                    User.countDocuments({"displayname": displayname}, function (err, count) {
                        if (err) console.log(err);
                        else if (count >= 1) res.redirect("/change/displayname?duplicateDisplayname=true");
                        else if (displayname.includes("*") || displayname.length > 20) res.redirect("/change/displayname?displaynameSwear=true");
                        else if (validName === false || displayname.length > 20) res.redirect("/change/displayname?displaynameError=true");
                        else {
                            User.updateOne({"_id": req.user._id}, {$set: {displayname: displayname}}, function (err, result) {
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
            if (email === "" || password === "") res.redirect("/change/email?error=true");
            else {
                User.countDocuments({"username": email}, function (err, count) {
                    if (err) console.log(err);
                    else if (count >= 1) res.redirect("/change/email?duplicateEmail=true");
                    else {
                        User.findOne({"_id": req.user._id}, function (err, user) {
                            if (err) console.log(err);
                            else {
                                bcrypt.compare(password, user.password, function (err, result) {
                                    if (err) res.redirect("/change/email?pwError=true");
                                    else if (result === false) res.redirect("/change/email?pwError=true");
                                    else {
                                        User.updateOne({"_id": req.user._id}, {$set: {username: email}}, function (err, result) {
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
            if (password === "" || passwordNew1 === "" || passwordNew2 === "") res.redirect("/change/password?error=true");
            else {
                User.findOne({"_id": req.user._id}, function (err, user) {
                    if (err) console.log(err);
                    else {
                        bcrypt.compare(password, user.password, function (err, result) {
                            if (err) res.redirect("/change/password?pwError=true");
                            else if (result === false) res.redirect("/change/password?pwError=true");
                            else if (passwordNew1 !== passwordNew2) res.redirect("/change/password?duplicatePwError=true");
                            else {
                                bcrypt.genSalt(10, function (err, salt) {
                                    if (err) console.log(err);
                                    else {
                                        bcrypt.hash(passwordNew2, salt, function (err, hash) {
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


app.post("/userProfile/:displayName", function (req, res) {
    var displayName = req.params.displayName;
    if (displayName !== undefined) displayName = validator.escape(displayName);
    
    var end = req.body.end;
    var goto = req.body.goto;
    var albumRemove = req.body.remove;
    var reorderedAlbum = req.body.reordered;

    if (end !== undefined) end = validator.escape(end);
    if (goto !== undefined) goto = validator.escape(goto);
    if (albumRemove !== undefined) albumRemove = validator.escape(albumRemove);
    if (reorderedAlbum !== undefined) reorderedAlbum = validator.escape(reorderedAlbum);

    User.findOne({displayname: displayName}, function (err, userId) {
        if (err) console.log(err);
        else {
            const userID = userId._id;
            //Jump to End of List
            if (end === "end") {
                Album.countDocuments({"userID": userID}, function (err, count) {
                    if (err) console.log(err);
                    else {
                        const finalPage = (Math.trunc(count/10) + 1);
                        if ((count % 10) === 0 && count > 10) res.redirect(displayName + "?page=" + (finalPage - 1));
                        else res.redirect(displayName + "?page=" + finalPage);
                    }
                });
            }

            //Page Select
            else if (goto === "goto") {
                var gotoPage = req.body.gotoPage;
                if (gotoPage !== undefined) gotoPage = validator.escape(gotoPage);

                gotoPage = parseInt(gotoPage);
                Album.findOne({"userID": userID, albumID: albumRemove}, {position: 1}, function (err, albumPos) {
                    if (err) console.log(err);
                    else {
                        Album.countDocuments({"userID": userID}, function (err, count) {
                            if (err) console.log(err);
                            else {
                                const pageLimit = (Math.trunc(count/10) + 1);
                                const page = (Math.trunc(albumPos/10) + 1);
                                if (gotoPage <= 0 || isNaN(gotoPage) || gotoPage > pageLimit) res.redirect(displayName + "?page=" + page + "&goto=true&gotoError=true");
                                else res.redirect(displayName + "?page=" + gotoPage);
                            }
                        });
                    }
                });
            }

            //Remove Album
            else if (albumRemove !== undefined) {
                if (!req.user) res.redirect(displayName + "?page=1");
                else if (userId.displayname !== req.user.displayname) res.redirect(displayName + "?page=1");
                else {
                    Album.findOne({"userID": userID, albumID: albumRemove}, {position: 1}, function (err, albumPos) {
                        if (err) console.log(err);
                        else {
                            Album.updateMany({"userID": userID, "position": {$gt: albumPos.position}}, {$inc: {position: -1}}, function (err, result) {
                                if (err) console.log(err);
                                else {
                                    Album.deleteOne({"userID": userID, albumID: albumRemove}, function (err, result) {
                                        if (err) console.log(err);
                                        else {
                                            var page = (Math.trunc(albumPos.position/10) + 1);
                                            if (albumPos.position % 10 === 0) page--;
                                            Album.countDocuments({"userID": userID}, function (err, count) {
                                                if (err) console.log(err);
                                                else {
                                                    setTimeout(function () {
                                                        if ((count % 10) === 0 && count >= 10) res.redirect(displayName + "?page=" + (page - 1) + "&reorder=true&removed=true");
                                                        else res.redirect(displayName + "?page=" + page + "&reorder=true&removed=true");
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
            }

            //Reorder Album
            else {
                if (!req.user) res.redirect(displayName + "?page=1");
                else if (userId.displayname !== req.user.displayname) res.redirect(displayName + "?page=1");
                else {
                    var newPos = req.body.newPos;
                    if (newPos !== undefined) newPos = validator.escape(newPos);
    
                    newPos = parseInt(newPos);
                    Album.find({"userID": userID, albumID: reorderedAlbum}, {albumID: 1, position: 1}, function (err, id) {
                        if (err) {
                            console.log(err);
                            res.redirect(displayName + "?page=1");
                        }
                        else {
                            var page = (Math.trunc(id[0].position/10) + 1);
                            if ((id[0].position % 10) === 0) page--;
                            if (id !== undefined) {
                                const currentPos = id[0].position;
                                const currentId = id[0].albumID;
    
                                Album.countDocuments({"userID": userID}, function (err, count) {
                                    if (err) console.log(err);
                                    else {
                                        if (newPos <= 0 || isNaN(newPos) || newPos > count) res.redirect(displayName + "?page=" + page + "&reorder=true&reorderError=true");
                                        else if (newPos === currentPos) res.redirect(displayName + "?page=" + page + "&reorder=true&samePos=true");
                                        else {
                                            if (newPos > currentPos) {
                                                var newPositionArray = new Array();
                                                for (i = currentPos; i <= newPos; i++) {
                                                    newPositionArray.push(i);
                                                }
                                                async.eachSeries(newPositionArray, async function (pos, done) {
                                                    const shiftUp = await Album.updateOne({"userID": userID, "position": pos}, {$set: {position: pos - 1}}, done);
                                                    if (pos === newPos) {
                                                        newPositionArray = [];
                                                        const final = await Album.updateOne({"userID": userID, "albumID": currentId}, {$set: {position: newPos}});
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
                                                    const shiftDown = await Album.updateOne({"userID": userID, "position": pos}, {$set: {position: pos + 1}}, done);
                                                    if (pos === newPos) {
                                                        newPositionArray = [];
                                                        const final = await Album.updateOne({"userID": userID, "albumID": currentId}, {$set: {position: newPos}});
                                                        return final;
                                                    }
                                                    else return shiftDown;
                                                });
                                            }
                                            setTimeout(function () {
                                                page = (Math.trunc(newPos/10) + 1);
                                                if ((newPos % 10) === 0) page--;
                                                res.redirect(displayName + "?page=" + page + "&reordered=true&reorder=true");
                                            }, 1250);
                                        }
                                    }
                                });
                            }
                            else res.redirect(displayName + "?page=" + page + "&reorder=true&reorderError=true");
                        }
                    });
                }
            }
        }
    });
});


app.post("/albumSearch", function (req, res) {
    var artistName = req.body.userArtist;
    var albumName = req.body.userAlbum;
    var albumYear = req.body.year;
    var discogsId = req.body.discogsId;

    if (artistName !== undefined) artistName = validator.escape(artistName);
    if (albumName !== undefined) albumName = validator.escape(albumName);
    if (albumYear !== undefined) albumYear = validator.escape(albumYear);
    if (discogsId !== undefined) discogsId = validator.escape(discogsId);

    if (artistName === "" && albumName === "" && albumYear === "") res.redirect("/albumSearch?error=true");

    else {
        if (discogsId !== undefined) {
            const regex = /^[0-9]+$/;
            const num = regex.test(discogsId);
            if (num === false) res.redirect("/albumSearch?discogsSearch=true&error=true");
            else {
                if (discogsId.length > 13) discogsId = discogsId.slice(0, 13);
                discogsId = parseInt(discogsId);
                db.search({master_id: discogsId}).then(function (searchResult) {
                    if (searchResult.results.length > 0) {
                        setTimeout(function () {
                            res.redirect("/album/" + searchResult.results[0].master_id);
                        }, 1000);
                    }
                    else res.redirect("/albumSearch?discogsSearch=true&notFound=true");
                });
            }
        }
    
        else {
            if (artistName === "" && albumName === "" && albumYear === "") res.redirect("/albumSearch?error=true");
            if (albumName.includes("&#x27;")) albumName = albumName.replace("&#x27;", "'");
            if (artistName.includes("&#x27;")) artistName = artistName.replace("&#x27;", "'");

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
                            res.redirect("/album/" + albumID1);
                        }, 1000);
                    } else if (albumID1 > albumID2) {
                        setTimeout(function () {
                            res.redirect("/album/" + albumID2);
                        }, 1000);
                    } else {
                        albumID1 = searchResult.results[0].master_id;
                        setTimeout(function () {
                            res.redirect("/album/" + albumID1);
                        }, 1000);
                    }
                }
                else {
                    res.redirect("/albumSearch?notFound=true");
                }
            });
        }
    }
});


app.post("/album/:albumId", function (req, res) {
    if (req.isAuthenticated()) {
        var album = req.params.albumId;
        if (album !== undefined) album = validator.escape(album);
    
        Album.countDocuments({"userID": req.user._id, "albumID": album}, function (err, result) {
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
                        
                        const censoredAlbums = require("./scripts/censoredAlbums");
                        if (censoredAlbums.includes(parseInt(album))) albumArt = "/censored.png";
                        else if (album == "24535" && data.images[5].uri !== undefined) albumArt = data.images[5].uri; //special case
                        else if (data.images[0].uri !== undefined) albumArt = data.images[0].uri;
    
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
                            if (data.genres.includes("Death Metal", "Goregrind", "Pornogrind")) albumArt = "/censored.png";
                        }
                            
                        if (data.styles !== undefined) {
                            for (i = 0; i < data.styles.length; i++) genreAlbum.push(" " + data.styles[i]);
                            if (data.styles.includes("Death Metal", "Goregrind", "Pornogrind")) albumArt = "/censored.png";
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
    
                        var addAlbum = req.body.add;
                        if (addAlbum !== undefined) addAlbum = validator.escape(addAlbum);

                        if (addAlbum === "added") {
                            Album.countDocuments({"userID": req.user._id}, function (err, count) {
                                if (err) console.log(err);
                                else {
                                    const albumAdd = new Album({
                                        albumID: album,
                                        userID: req.user._id,
                                        title: artistName + " - " + albumName,
                                        year: yearRelease,
                                        img: albumArt,
                                        albumTracks: tracklist,
                                        position: count + 1
                                    });
                                    albumAdd.save();
                                    setTimeout(function () {
                                        const page = Math.trunc(count/10);
                                        res.redirect("/userProfile/" + req.user.displayname + "?page=" + (page + 1) + "&added=true");
                                    }, 1250);
                                }
                            });
                        }
                        else {
                            var duplicate = req.query.duplicate;
                            if (duplicate !== undefined) duplicate = validator.escape(duplicate);

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
                                    duplicate: duplicate,
                                    list: req.user.displayname
                                });
                            }, 500);
                        }
                    }
                });
            }
        });
    } else res.redirect("/login");
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