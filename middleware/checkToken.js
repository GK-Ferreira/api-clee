const jwt = require('jsonwebtoken');

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ msg: 'Acesso negado' });
  }

  try {
    const secret = process.env.SECRET;
    const decodedToken = jwt.verify(token, secret);

    req.user = decodedToken;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      const refreshToken = req.cookies.refreshToken

      if (!refreshToken) {
        return res.status(401).json({ msg: 'Acesso negado. Token expirado e sem refresh token.' });
      }

      try {
        const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

        const newAccessToken = jwt.sign(
          { userId: decodedRefreshToken.userId },
          process.env.SECRET,
          { expiresIn: '5m' }
        );
        res.locals.newAccessToken = newAccessToken;

        next();
      } catch (refreshTokenError) {
        res.status(401).json({ msg: 'Token inválido ou expirado' });
      }
    } else {
      res.status(400).json({ msg: 'Token inválido' });
    }
  }
}

module.exports = checkToken;
