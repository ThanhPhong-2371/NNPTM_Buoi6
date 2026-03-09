let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')
module.exports = {
    checkLogin: async function (req, res, next) {
        let token
        if (req.cookies.token) {
            token = req.cookies.token
        } else {
            token = req.headers.authorization;
            if (!token || !token.startsWith("Bearer")) {
                res.status(403).send("ban chua dang nhap")
                return;
            }
            token = token.split(' ')[1];
        }
        let result = jwt.verify(token, 'secret');
        if (result && result.exp * 1000 > Date.now()) {
            req.userId = result.id;
            next();
        } else {
            res.status(403).send("ban chua dang nhap")
        }
    },
    checkRole: function (...requiredRole) {
        return async function (req, res, next) {
            let userId = req.userId;
            let user = await userController.FindUserById(userId);
            let currentRole = user.role.name.toLowerCase();
            let normalizedRequiredRoles = requiredRole.map(r => r.toLowerCase());

            if (currentRole === 'admin' || normalizedRequiredRoles.includes(currentRole)) {
                next();
            } else {
                res.status(403).send({ message: "ban khong co quyen" });
            }
        }
    },
    authorize: function (req, res, next) {

        const userId = req.userId;
        userController.FindUserById(userId).then(user => {
            const currentRole = user.role.name.toLowerCase();
            if (currentRole === 'admin') {
                return next();
            }
            if (currentRole === 'mod' && req.method === 'GET') {
                return next();
            }
            res.status(403).send({ message: "ban khong co quyen" });
        }).catch(err => {
            res.status(500).send({ message: "Internal Server Error" });
        });
    }
}