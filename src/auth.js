const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET is not set or shorter than 32 characters (see .env.example)');
}

const JWT_ALGORITHM = 'HS256';
const JWT_TTL = '1h';

function signToken(user) {
  return jwt.sign({ username: user.username }, JWT_SECRET, {
    algorithm: JWT_ALGORITHM,
    expiresIn: JWT_TTL,
    subject: String(user.id),
  });
}

function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ msg: 'Missing or malformed Authorization header' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
    req.user = { id: Number(payload.sub), username: payload.username };
    return next();
  } catch {
    return res.status(401).json({ msg: 'Invalid or expired token' });
  }
}

module.exports = { signToken, authenticate };
