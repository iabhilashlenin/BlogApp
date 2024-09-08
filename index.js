import express from 'express';
import 'dotenv/config'
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs from 'fs'
import path from 'path';
import { fileURLToPath } from 'url';
import { User } from './models/User.js';
import { Post } from './models/Post.js';
const app = express();

const uploadMiddleware = multer({ dest : 'uploads/'})

const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


app.use(cors({
    credentials: true,
    origin:process.env.CLIENT_URL
}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, '/uploads')));




//mongoDB connection 
mongoose.connect(process.env.MONGODB_URL)
.then(()=>{ console.log(`mongoDB connected `)})
.catch((error)=>{ console.error('Error connecting to MongoDB:', error.message);})

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    console.log("Request body:", req.body); // Log incoming request

    try {
        const hashedPassword = bcrypt.hashSync(password, salt);
        console.log("Hashed Password:", hashedPassword); // Log hashed password

        const userDoc = await User.create({
            username,
            password: hashedPassword, // Storing hashed password
        });

        console.log("User created:", userDoc); // Log successful user creation
        res.json(userDoc);
    } catch (e) {
        console.error("Error:", e); // Log the error
        res.status(400).json(e);
    }
});


app.post('/login',async (req,res)=>{
    const {username,password} = req.body;
    const userDoc = await User.findOne({username});
    const passOk = bcrypt.compareSync(password,userDoc.password);
    if(passOk){
        //logged in 
        jwt.sign({username,id:userDoc._id},secret,{},(err,token)=>{
            if(err) throw err;
            res.cookie('token',token).json({
                id: userDoc._id,
                username,
            });
        })
    }else{
        res.status(400).json('wrong credentials')
    }
})

app.get('/profile',(req,res)=>{
    const {token} = req.cookies;
    jwt.verify(token,secret,{},(err,info)=>{
        if(err) throw err;
        res.json(info);
    })
    res.json(req.cookies);
})
app.post('/logout',(req,res)=>{
    res.cookie('token','').json('ok')
})
app.post('/post',uploadMiddleware.single('file'),async (req,res)=>{
    const { originalname, filename, destination } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    const newFilename = filename + '.' + ext;
    const newPath = destination + '/' + newFilename;
    try {
        // Rename the file
          fs.renameSync(req.file.path, newPath);
    } catch (error) {
        console.error("Error renaming file: ", error);
        return res.status(500).json({ message: "File processing error" });
    }
    
    const coverPath = 'uploads/' + newFilename;
    const{token} = req.cookies;
    jwt.verify(token, secret, {}, async (err, info) => {
        if (err) {
            console.error('JWT verification failed:', err);
            return res.status(403).json({ message: 'Invalid token' });
        }
        const {title,summary,content} = req.body;
        const postDoc = await Post.create({
        title,
        summary,
        content,
        cover:coverPath,
        author:info.id
    })
   res.json(postDoc) 
    }) 
})
app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
    let newPath = null;

    if (req.file) {
        const { originalname, filename, destination } = req.file;
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1];
        const newFilename = filename + '.' + ext;
        newPath = destination + '/' + newFilename;
        try {
            // Rename the file
            fs.renameSync(req.file.path, newPath);
        } catch (error) {
            console.error("Error renaming file: ", error);
            return res.status(500).json({ message: "File processing error" });
        }
    }

    const { token } = req.cookies;
    jwt.verify(token, secret, {}, async (err, info) => {
        if (err) return res.status(403).json('Invalid token');
        
        const { id, title, summary, content } = req.body;
        const postDoc = await Post.findById(id);

        // Check if the user is the author
        const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
        if (!isAuthor) {
            return res.status(400).json('You are not the author');
        }

        // Update the post
        postDoc.set({
            title,
            summary,
            content,
            cover: newPath ? newPath : postDoc.cover
        });

        await postDoc.save();
        res.json(postDoc);
    });
});

app.get('/post',async (req,res)=>{
    res.json(await Post.find().populate('author',['username']))
})

app.get('/post/:id', async (req, res) => {
    const { id } = req.params;
  
    try {
      // Find post by ID and populate the 'author' field with the 'username'
      const postDoc = await Post.findById(id).populate('author', ['username']);
      
      // If the post is not found, return a 404 status
      if (!postDoc) {
        return res.status(404).json({ message: 'Post not found' });
      }

      // If post is found, send the post data
      res.json(postDoc);
    } catch (error) {
      // If there is an error (e.g., invalid ObjectId), return a 500 status
      console.error('Error fetching post:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });
  
  app.delete('/delete/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.cookies;

    // Verify JWT token
    jwt.verify(token, secret, {}, async (err, info) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(403).json('Invalid token');
        }

        try {
            // Find the post by ID
            const postDoc = await Post.findById(id);

            if (!postDoc) {
                console.error('Post not found with id:', id);
                return res.status(404).json('Post not found');
            }

            // Check if the user is the author
            const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
            if (!isAuthor) {
                console.error('User not authorized to delete this post');
                return res.status(400).json('You are not the author');
            }

            // Remove the post from the database
            await postDoc.deleteOne();

            // Optionally, delete the associated image file
            const filePath = path.join(__dirname, postDoc.cover);
            fs.unlink(filePath, (err) => {
                if (err) {
                    console.error('Error deleting image:', err);
                }
            });

            res.json({ message: 'Post deleted successfully' });
        } catch (error) {
            console.error('Error deleting post:', error);
            res.status(500).json('Server error');
        }
    });
});



app.listen(4000,()=>{
    console.log(`app running is port ${4000}`)
});
