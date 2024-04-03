const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({


    fname: {
        type: String,
        required: true,
        trim: true
    },

    lname: {
        type: String,
        required: true,
        trim: true
    },

    email: {
        type: String,
        required: true,
        unique: true
    },

    profileImage: {
        type: String,
        required: false
    }, 

    phone: {
        type: String,
        required: true,
        unique: true
    },

    password: {
        type: String,
        required: true,
    }, 
    show_password: {
        type: String,
        required: true,
    }, 
   

}, { timestamps: true })

module.exports = mongoose.model('User', userSchema)

