const express = require('express');
const cors = require('cors');
const { PrismaClient } = require("@prisma/client");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const emailValidator = require("email-validator");
const passwordValidator = require('password-validator');

const app = express();
const prisma = new PrismaClient();
const schema = new passwordValidator();

app.use(cors());
app.use(express.json());

const port = 4000;

/**
 * Middleware to verify JWT token
 * Adds the userId from the token to the request if valid
 */
const verifyToken = (req, res, next) => {
    const token = req.headers["x-access-token"];
    jwt.verify(token, process.env.SECRET_KEY, (error, decoded) => {
        if (error) {
            res.send({ error: "You session has expired or does not exist." });
            return;
        } else {
            req.userId = decoded.userId;
            next();
        }
    });
};

/**
 * Endpoint to login a user
 * Validates input, checks email and password, and returns a JWT token
 */
app.post('/login', 
    async (req, res) => {

    const loginData = req.body;
    if(!loginData.email || !loginData.password) {
        res.send({ error: "Please enter all fields." });
        return;
    }
    const user = await prisma.user.findUnique({
        where: { email: loginData.email }
    });
    if(!user) {
        res.send({ error: "Invalid credentials." });
        return;
    }
    const passwordValid = await bcrypt.compare(loginData.password, user.password);
    if(!passwordValid) {
        res.send({ error: "Invalid credentials." });
        return;
    }
    delete user.password;
    res.send({ token: jwt.sign({ userId: user.id }, process.env.SECRET_KEY) });
});

app.post('/register', async (req, res) => {

    const userData = req.body;

    if(!userData.email || 
        !userData.password || 
        !userData.fullName) 
        {
        res.send({ error: "Please enter all fields." });
        return;
    }
    const emailValid = emailValidator.validate(userData.email);
    if(!emailValid) {
        res.send({ error: "Please enter a valid email." });
        return;
    }
    schema
        .is().min(8)
        .is().max(100)
        .has().uppercase()
        .has().lowercase()
        .has().digits()
        .has().not().spaces();

    const passwordValid = schema.validate(userData.password);
    if(!passwordValid) {
        res.send({ error: "Please enter a valid password. Passwords must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one number." });
        return;
    }
    if(userData.fullName.length < 4) {
        res.send({ error: "Please enter a valid full name." });
        return;
    }
    const emailExists = await prisma.user.findUnique({
        where: { email: userData.email }
    });
    if(emailExists) {
        res.send({ error: "An account with that email already exists." });
        return;
    }
    let user;
    try {
        const hashedPassword = await bcrypt.hash(userData.password, 10);
        user = await prisma.user.create({
            data: {
                email: userData.email,
                password: hashedPassword,
                fullName: userData.fullName
            }
        });
    } catch(error) {
        res.send({ error: "An error occurred while creating your account." });
        return;
    }
    res.send({ message: "Your account has been created." });
});

app.post('/add-post', verifyToken, async (req, res) => {
    const userId = req.userId;
    const postData = req.body;
    if(!postData.postContent) {
        res.send({ error: "Please enter a post." });
        return;
    }
    if(postData.postContent.length < 7) {
        res.send({ error: "Please enter a longer post." });
        return;
    }
    const user = await prisma.user.findUnique({
        where: { id: userId }
    });
    if(!user) {
        res.send({ error: "User not found." });
        return;
    }

    const post = await prisma.post.create({
        data: {
            postContent: postData.postContent,
            user:{
                connect: { id: userId }
            }
        }
    });
    res.send({ success: "Post added." });
});

app.get('/get-posts', async (req, res) => {
    const posts = await prisma.post.findMany({
        include: { user: true }
    });
    res.send({ posts: posts });
}); 

app.delete('/delete-post/:postId', verifyToken, async (req, res) => {
    const userId = req.userId;
    const postId = parseInt(req.params.postId,10); // Get postId from URL parameters
    const post = await prisma.post.findUnique({
        where: { id: postId }
    });
    if(!post) {
        res.send({ error: "Post not found." });
        return;
    }
    if(post.userId !== userId) {
        res.send({ error: "You do not have permission to delete this post." });
        return;
    }
    await prisma.post.delete({
        where: { id: postId }
    });
    res.send({ success: "Post deleted." });
});
/**
 * Endpoint to get the current logged in user
 * Uses the verifyToken middleware to authenticate the user
 */
app.get('/current-user', verifyToken, async (req, res) => {
    const user = await prisma.user.findUnique({
        where: { id: req.userId }
    });
    delete user.password;
    res.send({ user: user });
});

/**
 * Endpoint to add a new post
 * Validates input, checks if user exists, and creates a new post
 */
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});

