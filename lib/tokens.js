const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// Never fall back to a known string: anyone who knows it can sign a TA token.
// Without JWT_SECRET, use a random per-process secret (tokens reset on restart).
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) {
  console.warn("JWT_SECRET is not set; using a random secret for this process.");
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role
    },
    SECRET,
    { expiresIn: "7d" }
  );
}

function readToken(header) {
  if (!header || !header.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  try {
    return jwt.verify(token, SECRET, { algorithms: ["HS256"] });
  } catch {
    return null;
  }
}

module.exports = { signToken, readToken };
