const mongoose = require("mongoose");

const albumSchema = new mongoose.Schema({
    albumID: Number,
    title: String,
    year: String,
    img: String,
    position: Number,
    albumTracks: [String]
});

const Album = new mongoose.model("Album", albumSchema);

module.exports = Album;