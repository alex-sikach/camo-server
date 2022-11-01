const logout = async (req, res) => {
    try {
        const headers = req.headers
        if(headers.cookie) {
            const sessionId = headers.cookie.split('=')[1]
            delete sessions[sessionId]
            res.set('Set-Cookie', 'session=; expires=Thu, 01 Jan 1970 00:00:00 GMT')
            res.send('Success')
        } else {
            res.send('Already logged out')
        }
    } catch (e) {
        console.log(e)
        res.status(500).send('Unexpected issue')
    }
}

module.exports.logout = logout