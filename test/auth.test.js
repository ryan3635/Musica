//Generated test script
const test = require("node:test");
const assert = require("node:assert");
const mongoose = require("mongoose");
require("dotenv").config();

const BASE = "http://localhost:3000";
const RUN = Date.now();                        // unique per run, so cleanup is safe
const email = `test${RUN}@example.com`;
const name = `test${RUN}`;
const password = "pw123";

// Submits a form the way a browser does.
// redirect:"manual" matters - otherwise fetch follows the 302 and we can't see it.
async function postForm(path, fields) {
    return fetch(BASE + path, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(fields).toString(),
        redirect: "manual"
    });
}

function redirectPath(res) {
    const location = res.headers.get("location");
    return location ? location.replace(BASE, "") : null;
}

test.before(async () => {
    mongoose.set("strictQuery", false);
    await mongoose.connect(process.env.MONGODB_TEST_URL);
});

test.after(async () => {
    const User = require("../models/user");
    await User.deleteMany({ username: new RegExp(String(RUN)) });
    await mongoose.disconnect();
});

test("register creates an account", async () => {
    const res = await postForm("/register", {
        username: email, displayname: name,
        passwordNew1: password, passwordNew2: password
    });

    assert.strictEqual(redirectPath(res), "/login?accCreated=true");

    // the redirect alone isn't proof - check the row actually exists
    const User = require("../models/user");
    const user = await User.findOne({ username: email });
    assert.ok(user, "user should be in the database");
    assert.notStrictEqual(user.password, password, "password must be hashed");
});

test("login with the correct password works", async () => {
    const res = await postForm("/login", { username: email, password });
    assert.strictEqual(redirectPath(res), "/userHome?loggedIn=true");
});

test("login with the wrong password is rejected", async () => {
    const res = await postForm("/login", { username: email, password: "nope" });
    assert.strictEqual(redirectPath(res), "/login?error=true");
});