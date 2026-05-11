const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/User");

const authMiddleware = require("../middleware/authMiddleware");
const roleMiddleware = require("../middleware/roleMiddleware");

const router = express.Router();


// REGISTER
router.post("/register", async (req, res) => {

    try {

        const { name, email, password, role } = req.body;

        const existingUser = await User.findOne({ email });

        if (existingUser) {

            return res.status(400).json({
                message: "Email already exists"
            });
        }

        const salt = await bcrypt.genSalt(10);

        const hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            name,
            email,
            password: hashedPassword,
            role
        });

        await user.save();

        res.status(201).json({
            message: "User Registered Successfully"
        });

    } catch (error) {

        res.status(500).json(error);
    }
});


// LOGIN
router.post("/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {

            return res.status(400).json({
                message: "Invalid Credentials"
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword) {

            return res.status(400).json({
                message: "Invalid Credentials"
            });
        }

        const token = jwt.sign(
            {
                id: user._id,
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1d"
            }
        );

        res.json({
            token
        });

    } catch (error) {

        res.status(500).json(error);
    }
});


// ADMIN ROUTE
router.get(
    "/admin/users",
    authMiddleware,
    roleMiddleware("admin"),

    async (req, res) => {

        const users = await User.find();

        res.json(users);
    }
);


// STUDENT PROFILE
router.get(
    "/student/profile",
    authMiddleware,
    roleMiddleware("student"),

    async (req, res) => {

        const user = await User.findById(req.user.id)
            .select("-password");

        res.json(user);
    }
);


// UPDATE PROFILE
router.put(
    "/student/profile",
    authMiddleware,
    roleMiddleware("student"),

    async (req, res) => {

        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            req.body,
            { new: true }
        );

        res.json(updatedUser);
    }
);


// DELETE USER
router.delete(
    "/admin/user/:id",
    authMiddleware,
    roleMiddleware("admin"),

    async (req, res) => {

        await User.findByIdAndDelete(req.params.id);

        res.json({
            message: "User Deleted"
        });
    }
);


// GET ALL USERS
router.get("/users", async (req, res) => {

    try {

        const users = await User.find();

        res.json(users);

    } catch (error) {

        res.status(500).json(error);
    }
});

module.exports = router;