const pool = require('../pool')

const getUsers = async (req, res) => {
    try {
        const headers = req.headers
        if(
            headers.cookie?.includes('session')
            && headers?.cookie[ headers?.cookie.indexOf('session')+7 ] === '='
        ) {
            const {start} = req.params;
            let {limit} = req.params;
            //check if the limit more than 10 users
            limit = limit <= 10 ? limit : 10;
            // get everything except password
            const users = (await pool?.query(
                'SELECT name, lastname, avatar, status, location FROM users WHERE id >= $1 LIMIT $2',
                [start, limit]
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

module.exports = getUsers