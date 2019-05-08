const jwt = require("jsonwebtoken");
const secrets = require("../secrets/secrets");

module.exports = (req, res, next) => {
  const token = req.headers.authorization;

  jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
    if (err) {
      res.status(401).json({ message: "Sorry try again" });
    } else {
      req.decodedToken = decodedToken;
      next();
    }
  });
};
