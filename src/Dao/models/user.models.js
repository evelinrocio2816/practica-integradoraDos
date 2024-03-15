const mongoose= require("mongoose")

const UserSchema=mongoose.Schema({
  
    first_name:{
        type: String,
        required: true
    },
    provider:{
        type: String,
        required: true
    },
    accountId:{
        type:String,
        required: true
    },
    last_name: {
        type: String,
       // required: true
    },
    email: {
        type:String,
        required : true,
        index: true, 
        unique: true
    },
    password:{
        type: String,
      // required: true
    },
    age: {
        type: Number,
      // required: true,
    },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'user'
    }
});

const UserModel = mongoose.model("user", UserSchema);
module.exports = UserModel;