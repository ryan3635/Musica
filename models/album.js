const mongoose = require("mongoose");

const albumSchema = new mongoose.Schema({
    albumID: Number,
    userID: {type: mongoose.Schema.Types.ObjectId, ref: "User"},
    title: String,
    artist: String,
    year: String,
    img: String,
    position: Number,
    trackNumber: [String],
    albumTracks: [String],
    trackLength: [String]
});

const Album = new mongoose.model("Album", albumSchema);

module.exports = Album;