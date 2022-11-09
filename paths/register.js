const pool = require('../pool')
const bcrypt = require("bcryptjs");

const register = async (req, res) => {
    try {
        const headers = req.headers
        if(
            headers.cookie?.includes('session')
            && headers?.cookie[ headers?.cookie.indexOf('session')+7 ] === '='
        ) {
            return res.send('Log out first')
        }
        const {
            username,
            password,
            name,
            lastname
        } = req.body;
        const friends = [];
        const album = [];
        if (
            !username
            || !name
            || !lastname
            || !password
            || password.length < 8
            || username.length < 8
        ) {
            return res.status(400).send('Invalid credentials')
        }
        const registered = Boolean((await pool?.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        )).rows.length === 1);
        if(registered) {
            res.status(409).send('already exists')
        } else {
            const hash = (await bcrypt.hash(password, 5));
            await pool?.query(
                "INSERT INTO users(username, password, name, lastname, friends, album) VALUES($1, $2, $3, $4, $5, $6)",
                [username, hash, name, lastname, friends, album]
            );
            res.send('Success')
        }
    } catch (e) {
        console.log(e)
        res.status(500).send('Unexpected issue')
    }
}

module.exports = register