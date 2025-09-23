const bcrypt = require('bcryptjs');

// Set your new password here
const password = 'Ancr0320!!';  // Use whatever password you want

const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync(password, salt);

console.log('\n=================================');
console.log('Your login password is:', password);
console.log('Put this hash in server.js:', hash);
console.log('=================================\n');