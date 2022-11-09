const express = require('express')
const cors = require('cors')
const pool = require('./pool')
const paths = require('./paths')

const app = express()

//middleware
app.use(cors())
app.use(express.json())

const port = process.env.PORT || 5000;

//ROUTES//
app.post('/register', paths?.register)
app.post('/login', paths?.login)
app.get('/logout', paths?.logout)
app.get('/users/delete', paths?.deleteAccount)
app.get('/users/:username', paths?.user)
app.get('/users/list/:start/:limit', paths?.usersList)

app.listen(port, async () => {
    try {
        console.log(`server has started on port ${port}`)
        await pool?.query(
            'DELETE FROM sessions'
        );
        await pool?.query(
            'ALTER SEQUENCE users_id_seq RESTART'
        );
    } catch (e) {
        console.log(e);
    }
})