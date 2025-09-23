const bcrypt = require('bcryptjs');

// Change this to your desired password
const password = 'ChattiSecure2024!';

const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync(password, salt);

console.log('\n=================================');
console.log('Password:', password);
console.log('Hash:', hash);
console.log('=================================\n');
console.log('Copy the hash above and add it to your server.js file');