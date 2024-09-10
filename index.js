const express = require('express')
const cors = require('cors')

const app = express()

//Config JSON response
app.use(express.json())

//Solve CORS
app.use(cors({credentials:true, origin:'http://localhost:3000'}))

app.use(express.static('public'))

//Routes

const UserRoutes = require('./routes/UserRoutes.js')
app.use('/users',UserRoutes)


app.listen(5000,()=>{console.log("servidor online")})