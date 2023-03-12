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
    } else res.render("home", {loggedOut: false});
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
        } else res.render("home", {loggedOut: true});
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
                    added: req.query.added
                });
            }
        });
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
                    const albumAdd = new userList({
                        albumID: album,
                        title: artistName + " - " + albumName,
                        year: "(" + yearRelease + ")",
                        img: albumArt,
                        albumTracks: tracklist
                    });
                    albumAdd.save();
                    setTimeout(function () {
                        res.redirect("/userProfile?added=true")
                    }, 1500);
                }
                else {
                    setTimeout(function () {
                        res.render("album", {
                            logged: true,
                            albumID: album,
                            artist: artistName,
                            title: albumName,
                            year: yearRelease,
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
                        year: yearRelease,
                        cover: albumArt,
                        videoMap: videoMap,
                        genre: genreAlbum,
                        tracks: tracklist
                    });
                }, 500);
            }
        }
    });
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
        const albumAdd = req.body.add;
        if (albumAdd === "added") res.redirect("/albumSearch");
    }
});


app.post("/albumSearch", function (req, res) {
    const artistName = req.body.userArtist;
    const albumName = req.body.userAlbum;
    const albumYear = req.body.year;

    if (artistName === "" && albumName === "" && albumYear === "") res.redirect("albumSearch?error=true");

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
                    }, 1250);
                } else if (albumID1 > albumID2) {
                    setTimeout(function () {
                        res.redirect("album/" + albumID2);
                    }, 1250);
                } else {
                    albumID1 = searchResult.results[0].master_id;
                    setTimeout(function () {
                        res.redirect("album/" + albumID1);
                    }, 1250);
                }
            }
            else {
                res.redirect("albumSearch?error=true");
            }
        });
    }
});


app.post("/album/:albumId", function (req, res) {
    const album = req.params.albumId;

    var artistName = "";
    var albumName = "";
    var yearRelease = "";
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
                    const albumAdd = new userList({
                        albumID: album,
                        title: artistName + " - " + albumName,
                        year: "(" + yearRelease + ")",
                        img: albumArt,
                        albumTracks: tracklist
                    });
                    albumAdd.save();
                    setTimeout(function () {
                        res.redirect("/userProfile?added=true")
                    }, 1500);
                }
                else {
                    setTimeout(function () {
                        res.render("album", {
                            logged: true,
                            albumID: album,
                            artist: artistName,
                            title: albumName,
                            year: yearRelease,
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
                        year: yearRelease,
                        cover: albumArt,
                        videoMap: videoMap,
                        genre: genreAlbum,
                        tracks: tracklist
                    });
                }, 500);
            }
        }
    });
});


app.listen(3000, function () {
    console.log("Server started!");
});