require('dotenv').config()
const express = require('express')
const massive = require('massive')
const session = require('express-session')
const authCtrl = require('./controllers/authController')
const authUser = require('./middlewares/authenticateUser')
const {SERVER_PORT, CONNECTION_STRING, SESSION_SECRET} = process.env

const app = express()

app.use(express.json())
app.use(session({
    resave: false,
    saveUninitialized: true,
    secret: SESSION_SECRET,
cookie: {maxAge: 1000*60*60*24*365} //this would be a year bc it's measured in milliseconds; default age of a cookie is infinite
}))

app.post('/auth/register', authCtrl.register)
app.post('/auth/login', authCtrl.login)
app.get('/auth/user', authCtrl.getUserSession)
app.delete('/auth/logout', authCtrl.logout)

//admins only
app.get('/api/secrets', authUser, (req, res) => res.status(200).send('here are the secrets'))

massive({
    connectionString: CONNECTION_STRING,
    ssl: {
        rejectUnauthorized: false
    }
}).then(dbInstance => {
    app.set('db', dbInstance)
    console.log('DB Ready')
    app.listen(SERVER_PORT, () => console.log(`Server ready on port ${SERVER_PORT}`))
})