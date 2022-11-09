const pool = require('../pool')

const getUser = async (req, res) => {
    try {
        const headers = req.headers
        if(
            headers.cookie?.includes('session')
            && headers?.cookie[ headers?.cookie.indexOf('session')+7 ] === '='
        ) {
            const {username} = req.params
            // get everything except password
            const users = (await pool?.query(
                'SELECT username, name, lastname, friends, avatar, status, album, location FROM users WHERE username = $1',
                [username]
            )).rows
            res.json(users)
        } else {
            res.send('Log in first')
        }
    } catch (e) {
        console.error(e.message)
        res.status(500).send('Unexpected issue')
    }
}

module.exports = getUser