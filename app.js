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
                    error: req.query.error,
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
    var genreAlbum = new Array();
    var tracklist = new Array();

    db.getMaster(album, function(err, data) {
        console.log(data);
        if (data.artists !== undefined) {
            artistName = data.artists[0].name;
            albumName = data.title;
            yearRelease = data.year;
            albumArt = data.images[0].uri;
    
            if (data.videos !== undefined) {
                var duplicates = new Array();
    
                for (i = 0; i < data.videos.length; i++) {
                    const artist = artistName + " - ";
                    const artistEnd = " - " + artistName;
                    const title = data.videos[i].title;
                    var titleDuplicate = "";
                    var vidTitle = "";
    
                    if (title.startsWith(artist) || title.startsWith(artistName + " – ") || title.startsWith(artist.toLowerCase()) || title.startsWith(artistName.toLowerCase() + " – ")) {
                        vidTitle = title.slice(artist.length, title.length);
                        titleDuplicate = vidTitle.toLowerCase();
                        if (!duplicates.includes(titleDuplicate)) {
                            videoTitle.push(vidTitle);
                            duplicates.push(titleDuplicate);
                            videoLink.push(data.videos[i].uri);
                        }
                    } 
                    else if (title.endsWith(artistEnd) || title.endsWith(" – " + artistName) || title.endsWith(artistEnd.toLowerCase()) || title.endsWith(" – " + artistName.toLowerCase())) {
                        vidTitle = title.slice(0, title.length - artistEnd.length);
                        titleDuplicate = vidTitle.toLowerCase();
                        if (!duplicates.includes(titleDuplicate)) {
                            videoTitle.push(vidTitle);
                            duplicates.push(titleDuplicate);
                            videoLink.push(data.videos[i].uri);
                        }
                    } 
                    else {
                        titleDuplicate = title.toLowerCase();
                        if (!duplicates.includes(titleDuplicate)) {
                            for (j = 0; j < data.tracklist.length; j++) {
                                titleDuplicate = data.tracklist[j].title.toLowerCase();
                                if (!duplicates.includes(titleDuplicate)) {
                                    videoTitle.push(title);
                                    duplicates.push(titleDuplicate);
                                    videoLink.push(data.videos[i].uri);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
    
            for (i = 0; i < data.genres.length; i++) {
                if (!genreAlbum.includes(" " + data.genres[i])) genreAlbum.push(" " + data.genres[i]);
            }
            for (i = 0; i < data.styles.length; i++) {
                if (!genreAlbum.includes(" " + data.styles[i])) genreAlbum.push(" " + data.styles[i]);
            }
    
            var trackNumber = 0;
            for (i = 0; i < data.tracklist.length; i++) {
                if (data.tracklist[i].type_ != 'heading' && data.tracklist[i].position != 'Video') {
                    trackNumber++;
                    if (data.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + data.tracklist[i].title);
                    else tracklist.push(trackNumber + ". " + data.tracklist[i].title + " (" + data.tracklist[i].duration + ")");
                }
            }
        } 
    });

    if (req.isAuthenticated()) {
        setTimeout(function () {
            res.render("album", {
                logged: true,
                artist: artistName,
                title: albumName,
                year: yearRelease,
                cover: albumArt,
                videoTitle: videoTitle,
                videoLink: videoLink,
                genre: genreAlbum,
                tracks: tracklist
            });
        }, 1500);
    } else {
        setTimeout(function () {
            res.render("album", {
                logged: false,
                artist: artistName,
                title: albumName,
                year: yearRelease,
                cover: albumArt,
                videoTitle: videoTitle,
                videoLink: videoLink,
                genre: genreAlbum,
                tracks: tracklist
            });
        }, 1500);
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

        if (artistName === "" && albumName === "" && albumYear === "") res.redirect("userProfile?error=true");

        else {
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
                        res.redirect("userProfile?added=true");
                    }, 1250);
                }
                else {
                    res.redirect("userProfile?error=true");
                }
            });
        }
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
                } else {
                    setTimeout(function () {
                        res.redirect("album/" + albumID2);
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
    var genreAlbum = new Array();
    var tracklist = new Array();

    db.getMaster(album, function(err, data) {
        console.log(data);
        if (data.artists !== undefined) {
            artistName = data.artists[0].name;
            albumName = data.title;
            yearRelease = data.year;
            albumArt = data.images[0].uri;

            if (data.videos !== undefined) {
                var duplicates = new Array();

                for (i = 0; i < data.videos.length; i++) {
                    const artist = artistName + " - ";
                    const artistEnd = " - " + artistName;
                    const title = data.videos[i].title;
                    var titleDuplicate = "";
                    var vidTitle = "";

                    if (title.startsWith(artist) || title.startsWith(artistName + " – ") || title.startsWith(artist.toLowerCase()) || title.startsWith(artistName.toLowerCase() + " – ")) {
                        vidTitle = title.slice(artist.length, title.length);
                        titleDuplicate = vidTitle.toLowerCase();
                        if (!duplicates.includes(titleDuplicate)) {
                            videoTitle.push(vidTitle);
                            duplicates.push(titleDuplicate);
                            videoLink.push(data.videos[i].uri);
                        }
                    } 
                    else if (title.endsWith(artistEnd) || title.endsWith(" – " + artistName) || title.endsWith(artistEnd.toLowerCase()) || title.endsWith(" – " + artistName.toLowerCase())) {
                        vidTitle = title.slice(0, title.length - artistEnd.length);
                        titleDuplicate = vidTitle.toLowerCase();
                        if (!duplicates.includes(titleDuplicate)) {
                            videoTitle.push(vidTitle);
                            duplicates.push(titleDuplicate);
                            videoLink.push(data.videos[i].uri);
                        }
                    } 
                    else {
                        titleDuplicate = title.toLowerCase();
                        if (!duplicates.includes(titleDuplicate)) {
                            for (j = 0; j < data.tracklist.length; j++) {
                                titleDuplicate = data.tracklist[j].title.toLowerCase();
                                if (!duplicates.includes(titleDuplicate)) {
                                    videoTitle.push(title);
                                    duplicates.push(titleDuplicate);
                                    videoLink.push(data.videos[i].uri);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            for (i = 0; i < data.genres.length; i++) {
                genreAlbum.push(" " + data.genres[i]);
            }
            for (i = 0; i < data.styles.length; i++) {
                genreAlbum.push(" " + data.styles[i]);
            }

            var trackNumber = 0;
            for (i = 0; i < data.tracklist.length; i++) {
                if (data.tracklist[i].type_ != 'heading' && data.tracklist[i].position != 'Video') {
                    trackNumber++;
                    if (data.tracklist[i].duration === '') tracklist.push(trackNumber + ". " + data.tracklist[i].title);
                    else tracklist.push(trackNumber + ". " + data.tracklist[i].title + " (" + data.tracklist[i].duration + ")");
                }
            }
        }
    });
    setTimeout(function () {
        res.render("album", {
            artist: artistName,
            title: albumName,
            year: yearRelease,
            cover: albumArt,
            videoTitle: videoTitle,
            videoLink: videoLink,
            genre: genreAlbum,
            tracks: tracklist
        });
    }, 1500);
});


app.listen(3000, function () {
    console.log("Server started!");
});