const mongoose = require('mongoose')
const Schema = mongoose.Schema

const Salas = new Schema({
   codigo:{
    type: Number,
    required:true,
    unique: true
   },
    nome:{
    type:String,
    required: true
   },
   status:{
    type:String,
    required: true
   },
   date_create:{
    type:Date,
    default:Date.now()
   },
   date_update:{
    type:Date,
    default:Date.now()
   },
   D_E_L_E_T:{
    type:String,
    default:''
   }
})

const Sala = mongoose.model('salas', Salas)
module.exports = Sala