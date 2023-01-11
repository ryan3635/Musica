const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


app.get("/login", function (req, res) {
    res.render("login");
});


app.get("/logout", function (req, res) {
    //todo
});


app.get("/register", function (req, res) {
    res.render("register");
});


app.get("/", function (req, res) {
    res.render("home");
});


app.get("/userHome", function (req, res) {
    res.render("userHome");
});


app.get("/userProfile", function (req, res) {
    //todo
});


app.post("/login", function (req, res) {
    //todo
});


app.post("/register", function (req, res) {
    //todo
});


app.listen(3000, function () {
    console.log("Server started!");
});