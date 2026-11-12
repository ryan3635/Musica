"use strict";
require('dotenv').config();

const dbUrl = process.env.NODE_ENV === "test" ? process.env.MONGODB_TEST_URL : process.env.MONGODB_URL;
if (!dbUrl) {
    throw new Error(
        process.env.NODE_ENV === "test" ? "MONGODB_TEST_URL is not set in .env" : "MONGODB_URL is not set in .env"
    );
}

const express = require("express");
const ejs = require("ejs");
const crypto = require("crypto");
const validator = require("validator");
const helmet = require("helmet");
const Discogs = require("disconnect").Client;
const db = new Discogs({consumerKey: process.env.DISCOGS_API_KEY, consumerSecret: process.env.DISCOGS_SECRET}).database();

const mongo = require("connect-mongo").default;
const mongoose = require("mongoose");
mongoose.set("strictQuery", false);
mongoose.set('sanitizeFilter', true);
mongoose.connect(dbUrl, {useNewUrlParser: true, useUnifiedTopology: true})
    .catch(function (err) {
        console.log("Unable to connect to database:", err.message);
        process.exit(1);
    }
);
const User = require("./models/user");
const Album = require("./models/album");

const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const nodemailer = require("nodemailer");
const emailer = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.NODEMAILER_USER,
        pass: process.env.NODEMAILER_PASS
    }
});

const censoredAlbums = require("./scripts/censoredAlbums");
const swearFilter = require("swearfilter");
const filter = new swearFilter({
    smartDetect: true,
    baseFilter: {
        useBaseFilter: true,
    }
});

const limiter = require("express-rate-limit");
const userAuthLimit = limiter({windowMs: 300000, limit: 10, handler: function (req, res) {res.redirect("/login?limitError=true")}});
const forgetPwLimit = limiter({windowMs: 600000, limit: 3, handler: function (req, res) {res.redirect("/forget?limitError=true")}});


const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));
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
    store: mongo.create({mongoUrl: dbUrl}),
    resave: false,
    saveUninitialized: false,
    cookie: {   //secure: true; once posted online (using https)
        httpOnly: true,
        secure: false
    }
}));
app.use(passport.initialize());
app.use(passport.authenticate("session"));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser (async function (id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

passport.use(new LocalStrategy (async function (username, password, done) {
    if (typeof username !== "string" || typeof password !== "string") return done(null, false);
    try {
        const user = await User.findOne({username: username});
        if (!user) return done(null, false);
        else {
            const auth = await bcrypt.compare(password, user.password);
            if (!auth) return done(null, false);
            else return done(null, user);
        }
    } catch (err) {
        return done(err);
    }
}));

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.URL + "/auth/google/userHome",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    async function (accessToken, refreshToken, profile, done) {
        try {
            const user = await User.findOneAndUpdate(
                {googleId: profile.id},
                {$setOnInsert: {googleId: profile.id}},
                {upsert: true, returnDocument: "after"}
            );
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

app.get("/auth/google",
    passport.authenticate('google', {scope: ["profile"]})
);

app.get("/auth/google/userHome",
    passport.authenticate('google', {failureRedirect: "/login"}),
    function (req, res) {
        res.redirect("/userHome");
});


app.get("/", function (req, res) {
    if (req.isAuthenticated()) {
        if (req.user.displayname === undefined) res.redirect("/change/displayname");
        else {
            const loggedIn = req.query.loggedIn;
            const googleDisplayname = req.query.googleDisplayname;
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
        const error = req.query.error;
        const limitError = req.query.limitError;
        const accCreated = req.query.accCreated;
        const pwReset = req.query.pwReset;
        const errCheck = {
            page: "Login",
            error: error,
            limitError: limitError,
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
        const error = req.query.error;
        const duplicatePwError = req.query.duplicatePwError;
        const duplicateEmail = req.query.duplicateEmail;
        const duplicateDisplayname = req.query.duplicateDisplayname;
        const displaynameError = req.query.displaynameError;
        const displaynameSwear = req.query.displaynameSwear;
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
        if (err) {
            console.log(err);
            res.redirect("/");
        }
        else {
            req.session.destroy(function (err) {
                if (err) {
                    console.log(err);
                    res.redirect("/");
                }
                else res.render("home", {loggedOut: true});
            });
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


app.get("/account", function (req, res) {
    if (req.isAuthenticated()) {
        const displaynameUpdate = req.query.displaynameUpdate;
        const emailUpdate = req.query.emailUpdate;
        const passwordUpdate = req.query.passwordUpdate;

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
        else {
            const message = {
                displaynameUpdate: displaynameUpdate,
                emailUpdate: emailUpdate,
                passwordUpdate: passwordUpdate,
                googleAcc: true,
                list: req.user.displayname
            }
            res.render("account", message);
        }
    }
    else res.redirect("/login");
});


app.get("/forget", function (req, res) {
    if (!req.isAuthenticated()) {
        const entered = req.query.entered;
        const error = req.query.error;
        const noEmail = req.query.noEmail;
        const limitError = req.query.limitError;
        const tokenExpired = req.query.tokenExpired;
        const message = {
            page: "Forget",
            entered: entered,
            error: error,
            noEmail: noEmail,
            limitError: limitError,
            tokenExpired: tokenExpired
        }
        res.render("forget", message);
    }
    else res.redirect("/loggedIn");
});


app.get("/passwordReset", async function (req, res) {
    if (!req.isAuthenticated()) {
        if (typeof req.query.userID === "string" && typeof req.query.token === "string" && req.query.userID && req.query.token) {
            const userID = req.query.userID;
            const token = req.query.token;
            const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

            try {
                const user = await User.findOne({"_id": userID, token: hashedToken, awaitingReset: true, tokenExpire: mongoose.trusted({$gt: Date.now()})});
                if (!user) res.redirect("/forget?tokenExpired=true");
                else {
                    const error = req.query.error;
                    const duplicatePwError = req.query.duplicatePwError;
                    const reset = {
                        error: error,
                        duplicatePwError: duplicatePwError,
                        userID: userID,
                        token: token
                    }
                    res.render("passwordReset", reset);
                }
            } catch (err) {
                console.log(err);
                res.redirect("/passwordReset?error=true");
            }
        }
        else res.redirect("/forget?tokenExpired=true");
    }
    else res.redirect("/loggedIn");
});


app.get("/change/:type", function (req, res) {
    if (req.isAuthenticated()) {
        const error = req.query.error;
        const pwError = req.query.pwError;
        const duplicatePwError = req.query.duplicatePwError;
        const duplicateEmail = req.query.duplicateEmail;
        const duplicateDisplayname = req.query.duplicateDisplayname;
        const displaynameError = req.query.displaynameError;
        const displaynameSwear = req.query.displaynameSwear;
        const type = req.params.type;

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


app.get("/userHome", function (req, res) {
    if (req.isAuthenticated()) {
        if (req.user.displayname === undefined) res.redirect("/change/displayname");
        else {
            const loggedIn = req.query.loggedIn;
            const googleDisplayname = req.query.googleDisplayname;
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


app.get("/userProfile/:displayName", async function (req, res) {
    const displayName = req.params.displayName;
    const yourList = req.user ? req.user.displayname : undefined;

    try {
        const userId = await User.findOne({displayname: displayName});
        if (!userId) res.redirect("/");
        else {
            const userID = userId._id;
            const page = req.query.page;
            const regex = /^[0-9]+$/;
            const validPage = regex.test(page);

            if (page === undefined || validPage === false) res.redirect("/userProfile/" + displayName + "?page=1");
            else {
                const albums = ((page - 1) * 10) + 1;
                const albumList = await Album.find({"position": mongoose.trusted({$gte: albums}), "userID": userID}, null, {sort: {position: 1}}).limit(10);
                const listSize = await Album.countDocuments({"userID": userID});
                const pageLimit = (Math.trunc(listSize/10) + 1);

                if ((listSize % 10) === 0 && listSize >= 10 && page == pageLimit) res.redirect("/userProfile/" + displayName + "?page=" + (pageLimit - 1));
                else if (page > pageLimit) res.redirect("/userProfile/" + displayName + "?page=" + pageLimit);
                else if (page <= 0) res.redirect("/userProfile/" + displayName + "?page=1");
                else {
                    const added = req.query.added;
                    const removed = req.query.removed;
                    const reordered = req.query.reordered;
                    const reorder = req.query.reorder;
                    const reorderError = req.query.reorderError;
                    const samePos = req.query.samePos;
                    const goto = req.query.goto;
                    const gotoError = req.query.gotoError;
                    const error = req.query.error;
                    const logged = !!req.user && userId.displayname === req.user.displayname;
                    res.render("userProfile", {
                        albumList: albumList,
                        added: added,
                        removed: removed,
                        reordered: reordered,
                        reorder: reorder,
                        reorderError: reorderError,
                        samePos: samePos,
                        page: page,
                        goto: goto,
                        gotoError: gotoError,
                        error: error,
                        listSize: listSize,
                        pages: pageLimit,
                        list: displayName,
                        yourList: yourList,
                        logged: logged,
                        loggedToolbar: !!req.user
                    });
                }
            }
        }
    } catch (err) {
        console.log(err);
        res.redirect("/userProfile?error=true");
    }
});


app.get("/albumSearch", function (req, res) {
    const notFound = req.query.notFound;
    const error = req.query.error;
    const discogsSearch = req.query.discogsSearch;

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


app.get("/album/:albumId", async function (req, res) {
    const album = req.params.albumId;
    let artistName = "";
    let albumName = "";
    let year = "";
    let albumArt = "";
    const videoTitle = new Array();
    const videoLink = new Array();
    let videoMap = new Map();
    const genreAlbum = new Array();
    const tracklist = new Array();
    
    const regex = /^[0-9]+$/;
    const num = regex.test(album);
    if (num === false) res.redirect("/albumSearch?notFound=true");
    else {
        const albumResult = await db.getMaster(album).catch(function (err) {
            console.log(err);
            return null;
        });
        if (!albumResult) res.redirect("/albumSearch?notFound=true");
        else {
            if (albumResult.artists) {
                artistName = albumResult.artists[0].name;
                albumName = albumResult.title;
                
                if (censoredAlbums.includes(parseInt(album))) albumArt = "/censored.png";
                else if (album == "24535" && albumResult.images?.[5]?.uri) albumArt = albumResult.images[5].uri; //alternate album cover
                else if (albumResult.images?.[0]?.uri) albumArt = albumResult.images[0].uri;
                
                if (albumResult.year) year = albumResult.year;
                else year = "";
                
                if (albumResult.videos) {
                    for (let i = 0; i < albumResult.videos.length; i++) {
                        const artist = artistName + " - ";
                        const artistEnd = " - " + artistName;
                        const title = albumResult.videos[i].title;
                        let vidTitle = "";
                        
                        if (title.startsWith(artist) || title.startsWith(artistName + " – ") || title.startsWith(artist.toLowerCase()) || title.startsWith(artistName.toLowerCase() + " – ")) {
                            vidTitle = title.slice(artist.length, title.length);
                            videoTitle.push(vidTitle);
                            videoLink.push(albumResult.videos[i].uri);
                        }
                        else if (title.endsWith(artistEnd) || title.endsWith(" – " + artistName) || title.endsWith(artistEnd.toLowerCase()) || title.endsWith(" – " + artistName.toLowerCase())) {
                            vidTitle = title.slice(0, title.length - artistEnd.length);
                            videoTitle.push(vidTitle);
                            videoLink.push(albumResult.videos[i].uri);
                        }
                        else {
                            videoTitle.push(albumResult.videos[i].title);
                            videoLink.push(albumResult.videos[i].uri);
                        }
                    }
                    
                    const videoTitleLower = new Array();
                    const videoMapTemp = new Map();
                    
                    for (let k = 0; k < videoTitle.length; k++) {
                        videoTitleLower.push(videoTitle[k].toLowerCase());
                        videoMapTemp.set(videoTitleLower[k], videoLink[k]);
                    }
                    videoMap = new Map ([...videoMapTemp].sort((a, b) => String(a[0]).localeCompare(b[0])));
                }
                
                if (albumResult.genres) {
                    for (let i = 0; i < albumResult.genres.length; i++) genreAlbum.push(" " + albumResult.genres[i]);
                    if (albumResult.genres.includes("Death Metal") || albumResult.genres.includes("Goregrind") || albumResult.genres.includes("Pornogrind"))
                        albumArt = "/censored.png";
                }
                
                if (albumResult.styles) {
                    for (let i = 0; i < albumResult.styles.length; i++) genreAlbum.push(" " + albumResult.styles[i]);
                    if (albumResult.styles.includes("Death Metal") || albumResult.styles.includes("Goregrind") || albumResult.styles.includes("Pornogrind"))
                        albumArt = "/censored.png";
                }
                
                if (albumResult.tracklist) {
                    let trackNumber = 0;
                    for (let i = 0; i < albumResult.tracklist.length; i++) {
                        if (albumResult.tracklist[i].type_ != 'heading' && albumResult.tracklist[i].position != 'Video') {
                            trackNumber++;
                            if (albumResult.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + albumResult.tracklist[i].title);
                            else tracklist.push(trackNumber + ". " + albumResult.tracklist[i].title + " (" + albumResult.tracklist[i].duration + ")");
                        }
                    }
                }
                
                if (req.isAuthenticated()) {
                    const duplicate = req.query.duplicate;
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
                }
                else {
                    const duplicate = req.query.duplicate;
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
                }
            }
            else res.redirect("/albumSearch?notFound=true");
        }
    }
});



app.post("/login", userAuthLimit, passport.authenticate("local", {successRedirect: "/userHome?loggedIn=true", failureRedirect: "/login?error=true"}));


app.post("/register", userAuthLimit, function (req, res) {
    const username = req.body.username;
    let displayname = req.body.displayname;
    const passwordNew1 = req.body.passwordNew1;
    const passwordNew2 = req.body.passwordNew2;

    if (typeof username !== "string" || !username || typeof displayname !== "string" || !displayname || typeof passwordNew1 !== "string" || !passwordNew1 || 
        typeof passwordNew2 !== "string" || !passwordNew2) res.redirect("/register?error=true");
    else if (!validator.isEmail(username)) res.redirect("/register?error=true");
    else if (req.isAuthenticated()) res.redirect("/loggedIn");
    else {
        if (passwordNew1 !== passwordNew2) {
            res.redirect("/register?duplicatePwError=true");
        }
        else {
            const regex = /^[a-zA-Z0-9]+$/;
            const validName = regex.test(displayname);
            User.countDocuments({"username": username}, function (err, count) {
                if (err) {
                    console.log(err);
                    res.redirect("/register?error=true");
                }
                else if (count >= 1) res.redirect("/register?duplicateEmail=true");
                else {
                    displayname = filter.censor(displayname);
                    User.countDocuments({"displayname": displayname}, function (err, count) {
                        if (err) {
                            console.log(err);
                            res.redirect("/register?error=true");
                        }
                        else if (count >= 1) res.redirect("/register?duplicateDisplayname=true");
                        else if (displayname.includes("*") || displayname.length > 20) res.redirect("/register?displaynameSwear=true");
                        else if (validName === false || displayname.length > 20) res.redirect("/register?displaynameError=true");
                        else {
                            bcrypt.genSalt(10, function (err, salt) {
                                if (err) {
                                    console.log(err);
                                    res.redirect("/register?error=true");
                                }
                                else {
                                    bcrypt.hash(passwordNew2, salt, function (err, hash) {
                                        if (err) {
                                            console.log(err);
                                            res.redirect("/register?duplicatePwError=true");
                                        }
                                        else {
                                            const newUser = new User({
                                                username: username,
                                                password: hash,
                                                displayname: displayname,
                                            });
                                            newUser.save(function (err) {
                                                if (err) {
                                                    if (err.code === 11000 && err.keyPattern.displayname) res.redirect("/register?duplicateDisplayname=true");
                                                    else if (err.code === 11000) res.redirect("/register?duplicateEmail=true");
                                                    else {
                                                        console.log(err);
                                                        res.redirect("/register?error=true");
                                                    }
                                                }
                                                else res.redirect("/login?accCreated=true");
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
});


app.post("/forget", forgetPwLimit, function (req, res) {
    const username = req.body.username;

    if (typeof username !== "string" || !username) res.redirect("/forget?error=true");
    else {
        User.countDocuments({username: username}, function (err, count) {
            if (err) {
                console.log(err);
                res.redirect("/forget?error=true");
            }
            else if (count < 1) res.redirect("/forget?noEmail=true");
            else {
                User.findOne({username: username}, {_id: 1}, function (err, id) {
                    if (err) {
                        console.log(err);
                        res.redirect("/forget?error=true");
                    }
                    else {
                        let token = "";
                        crypto.randomBytes(20, function (err, bytes) {
                            if (err) {
                                console.log(err);
                                res.redirect("/forget?error=true");
                            }
                            else {
                                const expireTime = Date.now() + 600000;
                                token = bytes.toString('hex');
                                const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

                                User.updateOne({"_id": id}, {"token": hashedToken, "tokenExpire": expireTime, "awaitingReset": true}, function (err, result) {
                                    if (err) {
                                        console.log(err);
                                        res.redirect("/forget?error=true");
                                    }
                                    else {
                                        const email = {
                                        from: process.env.NODEMAILER_USER,
                                        to: username,
                                        subject: "Musica Password Recovery",
                                        //update this html field when posted online
                                        html: "<h2>Password Reset</h2><p>Click the link below to reset your Musica account password. If you did not request this, please ingore this email.</p><br><a href='" + process.env.URL + "/passwordReset?userID=" + id._id + "&token=" + token + "'>Musica Password Reset</a>"
                                        }
                                        emailer.sendMail(email, function (err, info) {
                                            if (err) {
                                                console.log(err);
                                                res.redirect("/forget?error=true");
                                            }
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
        if (typeof req.query.userID === "string" && typeof req.query.token === "string" && req.query.userID && req.query.token) {
            const userID = req.query.userID;
            const passwordNew1 = req.body.passwordNew1;
            const passwordNew2 = req.body.passwordNew2;
            const token = req.query.token;
            const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

            if (typeof passwordNew1 !== "string" || typeof passwordNew2 !== "string" || !passwordNew1 || !passwordNew2) res.redirect("/passwordReset?userID=" + userID + "&token=" + token + "&error=true");
            else {
                if (passwordNew1 !== passwordNew2) res.redirect("/passwordReset?userID=" + userID + "&token=" + token + "&duplicatePwError=true");
                else {
                    User.findOne({"_id": userID, token: hashedToken, awaitingReset: true, tokenExpire: mongoose.trusted({$gt: Date.now()})}, function (err, user) {
                        if (err) {
                            console.log(err);
                            res.redirect("/passwordReset?error=true");
                        }
                        else if (!user) res.redirect("/forget?tokenExpired=true");
                        else {
                            bcrypt.genSalt(10, function (err, salt) {
                                if (err) {
                                    console.log(err);
                                    res.redirect("/passwordReset?error=true");
                                }
                                else {
                                    bcrypt.hash(passwordNew2, salt, function (err, hash) {
                                        if (err) {
                                            console.log(err);
                                            res.redirect("/passwordReset?error=true");
                                        }
                                        else {
                                            User.updateOne({"_id": userID}, {$set: {password: hash}, 
                                                                $unset: {token: 1, tokenExpire: 1, awaitingReset: 1}}, function (err, result) {
                                                if (err) {
                                                    console.log(err);
                                                    res.redirect("/passwordReset?error=true");
                                                }
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
        else res.redirect("/forget?tokenExpired=true");
    }
    else res.redirect("/loggedIn");
});


app.post("/change/:type", function (req, res) {
    if (req.isAuthenticated()) {
        let displayname = req.body.displayname;
        const email = req.body.email;
        const password = req.body.password;
        const passwordNew1 = req.body.passwordNew1;
        const passwordNew2 = req.body.passwordNew2;
        const type = req.params.type;

        if (type === "displayname") {
            const regex = /^[a-zA-Z0-9]+$/;
            const validName = regex.test(displayname);
            if (req.user.googleId === undefined) {
                if (typeof displayname !== "string" || !displayname || typeof password !== "string" || !password) res.redirect("/change/displayname?error=true");
                else {
                    displayname = filter.censor(displayname);
                    User.countDocuments({"displayname": displayname}, function (err, count) {
                        if (err) {
                            console.log(err);
                            res.redirect("/change/displayname?error=true");
                        }
                        else if (count >= 1) res.redirect("/change/displayname?duplicateDisplayname=true");
                        else if (displayname.includes("*") || displayname.length > 20) res.redirect("/change/displayname?displaynameSwear=true");
                        else if (validName === false || displayname.length > 20) res.redirect("/change/displayname?displaynameError=true");
                        else {
                            User.findOne({"_id": req.user._id}, function (err, user) {
                                if (err) {
                                    console.log(err);
                                    res.redirect("/change/displayname?error=true");
                                }
                                else {
                                    bcrypt.compare(password, user.password, function (err, result) {
                                        if (err) {
                                            console.log(err);
                                            res.redirect("/change/displayname?pwError=true");
                                        }
                                        else if (result === false) res.redirect("/change/displayname?pwError=true");
                                        else {
                                            if (displayname === "") res.redirect("/change/displayname?error=true");
                                            User.updateOne({"_id": req.user._id}, {$set: {displayname: displayname}}, function (err, result) {
                                                if (err) {
                                                    console.log(err);
                                                    res.redirect("/change/displayname?error=true");
                                                }
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
                if (typeof displayname != "string" || !displayname) res.redirect("/change/displayname?error=true");
                else {
                    displayname = filter.censor(displayname);
                    User.countDocuments({"displayname": displayname}, function (err, count) {
                        if (err) {
                            console.log(err);
                            res.redirect("/change/displayname?error=true");
                        }
                        else if (count >= 1) res.redirect("/change/displayname?duplicateDisplayname=true");
                        else if (displayname.includes("*") || displayname.length > 20) res.redirect("/change/displayname?displaynameSwear=true");
                        else if (validName === false || displayname.length > 20) res.redirect("/change/displayname?displaynameError=true");
                        else {
                            User.updateOne({"_id": req.user._id}, {$set: {displayname: displayname}}, function (err, result) {
                                if (err) {
                                    console.log(err);
                                    res.redirect("/change/displayname?error=true");
                                }
                                else res.redirect("/userHome?googleDisplayname=true");
                            });
                        }
                    });
                }
            }
        }

        else if (type === "email") {
            if (req.user.googleId !== undefined) res.redirect("/account");
            else if (typeof email !== "string" || !email || typeof password !== "string" || !password) res.redirect("/change/email?error=true");
            else if (!validator.isEmail(email)) res.redirect("/change/email?error=true");
            else {
                User.countDocuments({"username": email}, function (err, count) {
                    if (err) {
                        console.log(err);
                        res.redirect("/change/email?error=true");
                    }
                    else if (count >= 1) res.redirect("/change/email?duplicateEmail=true");
                    else {
                        User.findOne({"_id": req.user._id}, function (err, user) {
                            if (err) {
                                console.log(err);
                                res.redirect("/change/email?error=true");
                            }
                            else {
                                bcrypt.compare(password, user.password, function (err, result) {
                                    if (err) {
                                        console.log(err);
                                        res.redirect("/change/email?pwError=true");
                                    }
                                    else if (result === false) res.redirect("/change/email?pwError=true");
                                    else {
                                        User.updateOne({"_id": req.user._id}, {$set: {username: email}}, function (err, result) {
                                            if (err) {
                                                console.log(err);
                                                res.redirect("/change/email?error=true");
                                            }
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
            else if (typeof password !== "string" || !password || typeof passwordNew1 !== "string" || !passwordNew1 || typeof passwordNew2 !== "string" || !passwordNew2) res.redirect("/change/password?error=true");
            else {
                User.findOne({"_id": req.user._id}, function (err, user) {
                    if (err) {
                        console.log(err);
                        res.redirect("/change/password?error=true");
                    }
                    else {
                        bcrypt.compare(password, user.password, function (err, result) {
                            if (err) {
                                console.log(err);
                                res.redirect("/change/password?pwError=true");
                            }
                            else if (result === false) res.redirect("/change/password?pwError=true");
                            else if (passwordNew1 !== passwordNew2) res.redirect("/change/password?duplicatePwError=true");
                            else {
                                bcrypt.genSalt(10, function (err, salt) {
                                    if (err) {
                                        console.log(err);
                                        res.redirect("/change/password?error=true");
                                    }
                                    else {
                                        bcrypt.hash(passwordNew2, salt, function (err, hash) {
                                            if (err) {
                                                console.log(err);
                                                res.redirect("/change/password?duplicatePwError=true");
                                            }
                                            else {
                                                User.updateOne({"_id": req.user._id}, {$set: {password: hash}}, function (err, result) {
                                                    if (err) {
                                                        console.log(err);
                                                        res.redirect("/change/password?error=true");
                                                    }
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
    const displayName = req.params.displayName;
    const end = req.body.end;
    const goto = req.body.goto;
    const albumRemove = req.body.remove;
    const reorderedAlbum = req.body.reordered;

    User.findOne({displayname: displayName}, function (err, userId) {
        if (err) {
            console.log(err);
            res.redirect(displayName + "?page=1&error=true");
        }
        else if (!userId) res.redirect("/");
        else {
            const userID = userId._id;

            //Jump to End of List
            if (end === "end") {
                Album.countDocuments({"userID": userID}, function (err, count) {
                    if (err) {
                        console.log(err);
                        res.redirect(displayName + "?page=1&error=true");
                    }
                    else {
                        const finalPage = (Math.trunc(count/10) + 1);
                        if ((count % 10) === 0 && count > 10) res.redirect(displayName + "?page=" + (finalPage - 1));
                        else res.redirect(displayName + "?page=" + finalPage);
                    }
                });
            }

            //Page Select
            else if (goto === "goto") {
                const page = parseInt(req.body.page) || 1;
                const gotoPage = parseInt(req.body.gotoPage);

                Album.countDocuments({"userID": userID}, function (err, count) {
                    if (err) {
                        console.log(err);
                        res.redirect(displayName + "?page=1&gotoError=true");
                    }
                    else if (!count) res.redirect(displayName + "?page=1&gotoError=true");
                    else {
                        const pageLimit = (Math.trunc(count/10) + 1);
                        if (gotoPage <= 0 || isNaN(gotoPage) || gotoPage > pageLimit) res.redirect(displayName + "?page=" + page + "&goto=true&gotoError=true");
                        else res.redirect(displayName + "?page=" + gotoPage);
                    }
                });
            }

            //Remove Album
            else if (albumRemove !== undefined) {
                if (!req.user) res.redirect(displayName + "?page=1");
                else if (userId.displayname !== req.user.displayname) res.redirect(displayName + "?page=1");
                else {
                    Album.findOne({"userID": userID, albumID: albumRemove}, {position: 1}, function (err, albumPos) {
                        if (err) {
                            console.log(err);
                            res.redirect(displayName + "?page=1&error=true");
                        }
                        else if (!albumPos) res.redirect(displayName + "?error=true");
                        else {
                            Album.updateMany({"userID": userID, "position": mongoose.trusted({$gt: albumPos.position})}, {$inc: {position: -1}}, function (err, result) {
                                if (err) {
                                    console.log(err);
                                    res.redirect(displayName + "?page=1&error=true");
                                }
                                else {
                                    Album.deleteOne({"userID": userID, albumID: albumRemove}, function (err, result) {
                                        if (err) {
                                            console.log(err);
                                            res.redirect(displayName + "?page=1&error=true");
                                        }
                                        else {
                                            let page = (Math.trunc(albumPos.position/10) + 1);
                                            if (albumPos.position % 10 === 0) page--;
                                            Album.countDocuments({"userID": userID}, function (err, count) {
                                                if (err) {
                                                    console.log(err);
                                                    res.redirect(displayName + "?page=1&error=true");
                                                }
                                                else {
                                                    if ((count % 10) === 0 && count >= 10) res.redirect(displayName + "?page=" + (page - 1) + "&reorder=true&removed=true");
                                                    else res.redirect(displayName + "?page=" + page + "&reorder=true&removed=true");
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
                    let newPos = req.body.newPos;
                    newPos = parseInt(newPos);
                    Album.findOne({"userID": userID, albumID: reorderedAlbum}, {albumID: 1, position: 1}, function (err, album) {
                        if (err) {
                            console.log(err);
                            res.redirect(displayName + "?page=1&error=true");
                        }
                        else if (!album) res.redirect(displayName + "?page=1&reorderError=true");
                        else {
                            const currentPos = album.position;
                            const currentId = album.albumID;
                            let page = (Math.trunc(currentPos/10) + 1);
                            if ((currentPos % 10) === 0) page--;

                            Album.countDocuments({"userID": userID}, function (err, count) {
                                if (err) {
                                    console.log(err);
                                    res.redirect(displayName + "?page=1&error=true");
                                }
                                else {
                                    if (newPos <= 0 || isNaN(newPos) || newPos > count) res.redirect(displayName + "?page=" + page + "&reorder=true&reorderError=true");
                                    else if (newPos === currentPos) res.redirect(displayName + "?page=" + page + "&reorder=true&samePos=true");
                                    else {
                                        page = (Math.trunc(newPos/10) + 1);
                                        if ((newPos % 10) === 0) page--;
                                        //lower rank of album; other albums increase in rank
                                        if (newPos > currentPos) {
                                            Album.updateMany({"userID": userID, "position": mongoose.trusted({$gt: currentPos, $lte: newPos})}, {$inc: {position: -1}}, function (err, result) {
                                                if (err) {
                                                    console.log(err);
                                                    res.redirect(displayName + "?page=1&error=true");
                                                }
                                                else {
                                                    Album.updateOne({"userID": userID, "albumID": currentId}, {"position": newPos}, function (err, result) {
                                                        if (err) {
                                                            console.log(err);
                                                            res.redirect(displayName + "?page=1&error=true");
                                                        }
                                                        else res.redirect(displayName + "?page=" + page + "&reordered=true&reorder=true");
                                                    });
                                                }
                                            });
                                        }
                                        //increase rank of album; other albums decrease in rank
                                        else if (newPos < currentPos) {
                                            Album.updateMany({"userID": userID, "position": mongoose.trusted({$gte: newPos, $lt: currentPos})}, {$inc: {position: +1}}, function (err, result) {
                                                if (err) {
                                                    console.log(err);
                                                    res.redirect(displayName + "?page=1&error=true");
                                                }
                                                else {
                                                    Album.updateOne({"userID": userID, "albumID": currentId}, {"position": newPos}, function (err, result) {
                                                        if (err) {
                                                            console.log(err);
                                                            res.redirect(displayName + "?page=1&error=true");
                                                        }
                                                        else res.redirect(displayName + "?page=" + page + "&reordered=true&reorder=true");
                                                    });
                                                }
                                            });
                                        }
                                        else res.redirect(displayName + "?page=1&error=true");
                                    }
                                }
                            });
                        }
                    });
                }
            }
        }
    });
});


app.post("/albumSearch", async function (req, res) {
    const artistName = req.body.userArtist;
    const albumName = req.body.userAlbum;
    const albumYear = req.body.year;
    let discogsId = req.body.discogsId;

    if (artistName === "" && albumName === "" && albumYear === "") res.redirect("/albumSearch?error=true");
    else {
        if (discogsId !== undefined) {
            const regex = /^[0-9]+$/;
            const num = regex.test(discogsId);
            if (num === false) res.redirect("/albumSearch?discogsSearch=true&error=true");
            else {
                if (discogsId.length > 13) discogsId = discogsId.slice(0, 13);
                discogsId = parseInt(discogsId);
                try {
                    const searchResult = await db.search({master_id: discogsId});
                    if (searchResult.results.length > 0) res.redirect("/album/" + searchResult.results[0].master_id);
                    else res.redirect("/albumSearch?discogsSearch=true&notFound=true");
                } catch (err) {
                    console.log(err);
                    res.redirect("/albumSearch?discogsSearch=true&error=true");
                }
            }
        }
    
        else {
            try {
                const searchResult = await db.search({artist: artistName, release_title: albumName, year: albumYear, type: "master"});
                let albumID1 = 99999999999999;
                let albumID2 = 99999999999999;
                if (searchResult.results.length > 0) {
                    //prefer US album art
                    let i = searchResult.results.findIndex(album => album.country === "US");
                    while (i >= 0 && i < searchResult.results.length) {
                        const albumID1temp = searchResult.results[i].master_id;
                        if (albumID1temp < albumID1 && searchResult.results[i].country === "US") {
                            albumID1 = albumID1temp;
                        }
                        i++;
                    }

                    //prefer UK album art if US not found
                    let j = searchResult.results.findIndex(album => album.country === "UK");
                    while (j >= 0 && j < searchResult.results.length) {
                        const albumID2temp = searchResult.results[j].master_id;
                        if (albumID2temp < albumID2 && searchResult.results[j].country === "UK") {
                            albumID2 = albumID2temp;
                        } 
                        j++;
                    }

                    if (albumID1 < albumID2) res.redirect("/album/" + albumID1);
                    else if (albumID1 > albumID2) res.redirect("/album/" + albumID2);
                    else {
                        albumID1 = searchResult.results[0].master_id;
                        res.redirect("/album/" + albumID1);
                    }
                }
                else {
                    res.redirect("/albumSearch?notFound=true");
                }
            } catch (err) {
                console.log(err);
                res.redirect("/albumSearch?error=true");
            }
        }
    }
});


app.post("/album/:albumId", async function (req, res) {
    if (req.isAuthenticated()) {
        const album = req.params.albumId;
        const regex = /^[0-9]+$/;
        const num = regex.test(album);
        if (num === false) res.redirect("/albumSearch?notFound=true");
        else {
            try {
                const albumDuplicate = await Album.countDocuments({"userID": req.user._id, "albumID": album});
                if (albumDuplicate > 0) res.redirect("/album/" + album + "?duplicate=true");
                else {
                    let artistName = "";
                    let albumName = "";
                    let year = "";
                    let albumArt = "";
                    const genreAlbum = new Array();
                    const trackNumbers = new Array();
                    const tracklist = new Array();
                    const trackLength = new Array();
                    
                    const albumResult = await db.getMaster(album).catch(function (err) {
                        console.log(err);
                        return null;
                    });
                    if (!albumResult) {
                        res.redirect("/albumSearch?notFound=true");
                    }
                    else if (albumResult.artists) {
                        artistName = albumResult.artists[0].name;
                        albumName = albumResult.title;
                        
                        if (censoredAlbums.includes(parseInt(album))) albumArt = "/censored.png";
                        else if (album == "24535" && albumResult.images?.[5]?.uri) albumArt = albumResult.images[5].uri; //alternate album cover for specific album
                        else if (albumResult.images?.[0]?.uri) albumArt = albumResult.images[0].uri;
                        
                        if (albumResult.year) year = albumResult.year;
                        else year = "";
                        
                        if (albumResult.genres) {
                            for (let i = 0; i < albumResult.genres.length; i++) genreAlbum.push(" " + albumResult.genres[i]);
                            if (albumResult.genres.includes("Death Metal") || albumResult.genres.includes("Goregrind") || albumResult.genres.includes("Pornogrind"))
                                albumArt = "/censored.png";
                        }
                        
                        if (albumResult.styles) {
                            for (let i = 0; i < albumResult.styles.length; i++) genreAlbum.push(" " + albumResult.styles[i]);
                            if (albumResult.styles.includes("Death Metal") || albumResult.styles.includes("Goregrind") || albumResult.styles.includes("Pornogrind"))
                                albumArt = "/censored.png";
                        }
                        
                        if (albumResult.tracklist) {
                            let trackNumber = 0;
                            for (let i = 0; i < albumResult.tracklist.length; i++) {
                                if (albumResult.tracklist[i].type_ != 'heading' && albumResult.tracklist[i].position != 'Video') {
                                    trackNumber++;
                                    if (albumResult.tracklist[i].duration === '') {
                                        trackNumbers.push(trackNumber);
                                        tracklist.push(albumResult.tracklist[i].title);
                                    }
                                    else {
                                        trackNumbers.push(trackNumber);
                                        tracklist.push(albumResult.tracklist[i].title);
                                        trackLength.push(albumResult.tracklist[i].duration);
                                    }
                                }
                            }
                        }
                        
                        const addAlbum = req.body.add;
                        if (addAlbum === "added") {
                            const albumCount = await Album.countDocuments({"userID": req.user._id});
                            const page = Math.trunc(albumCount/10);
                            const albumAdd = new Album({
                                albumID: album,
                                userID: req.user._id,
                                title: albumName,
                                artist: artistName,
                                year: year,
                                img: albumArt,
                                trackNumber: trackNumbers,
                                albumTracks: tracklist,
                                trackLength: trackLength,
                                position: albumCount + 1
                            });
                            await albumAdd.save();
                            res.redirect("/userProfile/" + req.user.displayname + "?page=" + (page + 1) + "&added=true");
                        } else res.redirect("/album/" + album);
                    }
                    else res.redirect("/albumSearch?notFound=true");
                }
            } catch (err) {
                if (err.code === 11000) res.redirect("/album/" + album + "?duplicate=true");
                else {
                    console.log(err);
                    res.redirect("/albumSearch?error=true");
                }
            }
        }
    }
    else res.redirect("/login");
});


app.use(function (req, res) {
    res.status(404).render("pageNotFound");
});

app.use(function (err, req, res, next) {
    console.log(err);
    res.status(500).render("pageError");
});

app.listen(process.env.PORT || 3000, function (err) {
    if (err) {
        console.log("Server cannot be started:", err.message);
        process.exit(1);
    }
    console.log("Server started!");
    setInterval(async function() {
        try {
            await User.updateMany(
                {"awaitingReset": true, "tokenExpire": mongoose.trusted({$lte: new Date()})},
                {$unset: {token: 1, tokenExpire: 1, awaitingReset: 1}}
            );
        }
        catch (err) {
            console.log(err);
        }
        
    }, 600000);
});