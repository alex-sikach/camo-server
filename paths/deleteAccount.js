const pool = require('../pool')

const deleteAccount = async (req, res) => {
    try {
        const headers = req.headers
        if(
            headers.cookie?.includes('session')
            && headers?.cookie[ headers?.cookie.indexOf('session')+7 ] === '='
        ) {
            const sessionId = headers.cookie.split('=')[1]
            const {username} = (await pool?.query(
                'SELECT username FROM sessions WHERE id = $1',
                [sessionId]
            )).rows[0];
            await pool?.query(
                'DELETE FROM sessions WHERE id = $1',
                [sessionId]
            )
            res.clearCookie('session')
            await pool?.query(
                "DELETE FROM users WHERE username = $1",
                [username]
            );
            res.send('Success')
        } else {
            res.send('Log in first')
        }

    } catch (e) {
        console.log(e)
        res.status(500).send('Unexpected issue')
    }
}

module.exports = deleteAccount