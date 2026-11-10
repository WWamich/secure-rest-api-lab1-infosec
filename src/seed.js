require('dotenv').config();

const bcrypt = require('bcryptjs');
const db = require('./db');

const [username, password] = process.argv.slice(2);

if (!username || !password || password.length < 8 || password.length > 72) {
  console.error('Usage: npm run seed -- <username> <password (8..72 chars)>');
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12);

const info = db
  .prepare('INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)')
  .run(username, hash);

console.log(info.changes ? `User "${username}" created` : `User "${username}" already exists`);
