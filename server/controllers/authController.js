const bcrypt = require('bcryptjs')

module.exports = {   
    register: async (req, res) => {
        //To do: receive the needed info (name, email, pw, admin) from req.body
        const db = req.app.get('db')
        const {name, email, password, admin} = req.body

        //To do: check if they are already registered; if yes, reject request
        const [existingUser] = await db.get_user_by_email([email]) //this destructres an array & assigns index 0 to the variable name

        if(existingUser) {
            return res.status(409).send('User already exists')
        }

        //To do: If not registered, hash the pw
        const salt = bcrypt.genSaltSync(10)

        const hash = bcrypt.hashSync(password, salt)

        //To do: insert into db
        const newUser = await db.register_user([name, email, hash, admin])

         //To do: attach that user to the session
        req.session.user=newUser

        //To do: send confirmation of registration
        res.status(200).send(newUser)
    },
    
    login: async (req, res) => {
        //To do: get necessary info off of req.body (email, pw)
        const db = req.app.get('db')

        const {email, password} = req.body

        //To do: check if user exists; if not, reject the reques
        const [existingUser] = await db.get_user_by_email([email])

        if(!existingUser) {
            return res.status(404).send('User does nto exist')
        }

        //To do: check pw against the hash; if mismatch, reject the request
        const isAuthenticated = bcrypt.compareSync(password, existingUser.hash)
        
        if(!isAuthenticated) {
            return res.status(403).send('Incorrect password')
        }

        //to do: delete the hash fromn the user object
        delete existingUser.hash

        //to do: attach the user to the session
        req.session.user=existingUser
        
        //to do: send back confirmation of login
        res.status(200).send(existingUser)

    },
    getUserSession: (req, res) => {
        if (req.session.user) {
            res.status(200).send(req.session.user)
        } else {
            res.status(404).send('No session found')
        }

    },
    logout: (req, res) => {
        req.session.destroy()
        res.sendStatus(200)
    }
}