const express = require('express');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());

// Function to read and write JSON data from keys.json
const readKeysFromFile = () => {
    const data = fs.readFileSync('keys.json', 'utf-8');
    return JSON.parse(data);
};

const writeKeysToFile = (keys) => {
    fs.writeFileSync('keys.json', JSON.stringify(keys, null, 2));
};

// Route to generate a key
app.post('/generateKey', async (req, res) => {
    const { username, password, expirationHours } = req.body;

    if (!username || !password || !expirationHours) {
        return res.status(400).send('All fields are required.');
    }

    // Hash the password
    const passwordHash = await bcrypt.hash(password, 10);

    // Generate the key
    const expirationTime = new Date();
    expirationTime.setHours(expirationTime.getHours() + parseInt(expirationHours));

    const generatedKey = `${username}-${Buffer.from(password).toString('base64')}-${expirationTime.toISOString()}`;

    // Read existing keys
    const keys = readKeysFromFile();

    // Store the new key
    const newKey = {
        username,
        passwordHash,
        generatedKey,
        expirationTime: expirationTime.toISOString()
    };

    keys.push(newKey);
    writeKeysToFile(keys);

    res.json({ generatedKey });
});

// Route to validate the key
app.post('/validateKey', async (req, res) => {
    const { enteredKey, username, password } = req.body;

    const keys = readKeysFromFile();

    // Find the matching key
    const key = keys.find((key) => key.username === username);

    if (!key) {
        return res.status(404).send('Key not found.');
    }

    // Check if the key is expired
    const currentTime = new Date();
    if (new Date(key.expirationTime) < currentTime) {
        return res.status(400).send('Key has expired.');
    }

    // Validate the password
    const isPasswordValid = await bcrypt.compare(password, key.passwordHash);
    if (!isPasswordValid || enteredKey !== key.generatedKey) {
        return res.status(400).send('Invalid key or credentials.');
    }

    res.send('Login Successful!');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
