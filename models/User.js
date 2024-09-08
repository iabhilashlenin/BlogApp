import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username:{
        type: String,
        required: true,
        min: 4,
        unique: true
    },
    password: {
        type: String,
        required: true,
    }
})
 export const User = new mongoose.model('User',userSchema);
