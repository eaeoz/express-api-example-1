require('dotenv').config(); // Load environment variables from .env file
const { body, validationResult } = require('express-validator');
const express = require('express');
const r = require('rethinkdb');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto'); // Import crypto module
const app = express();
const port = process.env.PORT || 3000; // Use environment variable for port
const rateLimit = require('express-rate-limit');
const cors = require('cors'); // Import cors
const helmet = require('helmet');
// Create a rate limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.'
});

// Apply the rate limiter to all requests
app.use(limiter);
app.use(helmet());
app.use(cors({
    origin: 'http://localhost:3000', // Adjust this to your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed methods
    credentials: true // Allow credentials (if needed)
}));
app.options('/api/login', cors()); // Enable preflight for this route
app.use(express.json()); // Middleware to parse JSON bodies
// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');


// Generate a random secret key if not defined
if (!process.env.SECRET_KEY) {
    const secretKey = crypto.randomBytes(32).toString('hex');
    console.log('Generated Secret Key:', secretKey);
    process.env.SECRET_KEY = secretKey; // Set the generated key to the environment variable
}

// Database Configuration
const rethinkdbHost = process.env.RETHINKDB_HOST || 'localhost';
const rethinkdbPort = process.env.RETHINKDB_PORT || 28015;
const rethinkdbDb = process.env.RETHINKDB_DB || 'test';
let conn;

// Connect to RethinkDB and ensure necessary tables exist
const connectToDatabase = async () => {
    try {
        conn = await r.connect({ host: rethinkdbHost, port: rethinkdbPort });
        const dbs = await r.dbList().run(conn);

        if (!dbs.includes(rethinkdbDb)) {
            await r.dbCreate(rethinkdbDb).run(conn);
            console.log(`Database '${rethinkdbDb}' created successfully.`);
        } else {
            console.log(`Database '${rethinkdbDb}' already exists.`);
        }

        conn.use(rethinkdbDb);

        // Ensure necessary tables exist
        const tables = await r.tableList().run(conn);
        const requiredTables = ['users', 'messages', 'posts'];

        for (const table of requiredTables) {
            if (!tables.includes(table)) {
                await r.tableCreate(table).run(conn);
                console.log(`Table '${table}' created successfully.`);
            } else {
                console.log(`Table '${table}' already exists.`);
            }
        }

        console.log('Connected to RethinkDB');
    } catch (err) {
        console.error('Error connecting to RethinkDB:', err);
        process.exit(1); // Exit the application on connection error
    }
};

// Authentication Middleware
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        console.log('ERROR: Token is required.');
        return res.status(403).send('Token is required.');
    }

    // Extract the token from the Bearer format
    const bearerToken = token.split(' ')[1];
    console.log('INFO: Verifying token:', bearerToken);

    jwt.verify(bearerToken, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            console.log('ERROR: Invalid token.', err.message);
            return res.status(403).send('Invalid token.');
        }
        req.user = user;
        console.log('SUCCESS: Token verified for user:', user.id);
        next();
    });
};

// Resource Access Control Middleware
const checkResourceAccess = async (req, res, next) => {
    const resourceId = req.params.id;

    try {
        // Fetch user data from the database
        const cursor = await r.table('users').get(req.user.id).run(conn);
        if (!cursor) {
            return res.status(404).send('User not found.');
        }

        // Check if the user is trying to access their own resource
        if (cursor.id === resourceId) {
            return next(); // User can access their own resource
        }

        // If accessing another user's resource, deny access
        console.log('ERROR: Access denied for user:', req.user.id);
        return res.status(403).send('Access denied: You do not have permission to access this resource.');
    } catch (dbError) {
        console.error('Database error:', dbError);
        return res.status(500).send('Internal server error.');
    }
};

// User Registration Route
app.post('/api/register', async (req, res) => {
    const { username, password, groupId } = req.body;

    // Check if the user already exists
    const existingUserCursor = await r.table('users').filter({ username }).run(conn);
    const existingUsers = await existingUserCursor.toArray();

    if (existingUsers.length > 0) {
        return res.status(400).json({ error: 'User already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await r.table('users').insert({ username, password: hashedPassword, groupId }).run(conn);
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (err) {
        return res.status(500).json({ error: 'Error registering user: ' + err.message });
    }
});

// User Login Route with Basic Auth
app.post('/api/login', [body('username').isEmail(), body('password').isLength({ min: 5 })], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    // Proceed with login
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        console.log('ERROR: Authorization header is required.');
        return res.status(401).send('Authorization header is required.');
    }

    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');

    try {
        const cursor = await r.table('users').filter({ username }).run(conn);
        const users = await cursor.toArray();

        if (users.length === 0) {
            console.log('ERROR: Invalid credentials for username:', username);
            return res.status(401).send('Invalid credentials.');
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            console.log('ERROR: Invalid credentials for username:', username);
            return res.status(401).send('Invalid credentials.');
        }

        // Generate token with expiration
        const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, { expiresIn: '1h' }); // Token valid for 1 hour
        console.log('SUCCESS: User logged in successfully:', username);

        // Return token and user ID
        res.json({ token, userId: user.id });
    } catch (err) {
        console.error('ERROR: Error logging in:', err.message);
        return res.status(500).send('Error logging in: ' + err.message);
    }
});

// Retrieve User's Own Messages related to Specific User
app.get('/api/:id/messages/:toid', authenticate, checkResourceAccess, async (req, res) => {
    const fromUID = req.params.id; // Sender's ID from the URL
    const toUID = req.params.toid; // Recipient's ID from the URL

    try {
        const cursor = await r.db('test_db').table('messages')
            .filter((message) =>
                (message('FROMUID').eq(fromUID).and(message('ToUID').eq(toUID)))
                    .or(message('FROMUID').eq(toUID).and(message('ToUID').eq(fromUID)))
            )
            .run(conn);

        const messages = await cursor.toArray();

        if (messages.length === 0) {
            return res.status(404).json({ message: 'No messages found.' });
        }

        res.status(200).json({ messages });
    } catch (err) {
        console.error('ERROR: Error retrieving messages:', err.message);
        return res.status(500).send('Error retrieving messages: ' + err.message);
    }
});

// Retrieve Posts for a User
app.get('/api/:id/posts', authenticate, checkResourceAccess, async (req, res) => {
    const userId = req.params.id;

    try {
        const postsCursor = await r.table('posts')
            .filter({ UserID: userId }) // Filter posts created by the user
            .orderBy(r.desc('Timestamp')).limit(50) // Order by timestamp descending
            .run(conn);

        const posts = await postsCursor.toArray();
        res.json(posts);
    } catch (err) {
        console.error('ERROR: Error retrieving posts:', err.message);
        return res.status(500).send('Error retrieving posts: ' + err.message);
    }
});

// Post a New Message
app.post('/api/messages', authenticate, async (req, res) => {
    const { FROMUID, ToUID, MessageText, SentDt } = req.body;

    try {
        const newMessage = {
            FROMUID,
            ToUID,
            MessageText,
            ReadStatus: 'Unread',
            SentDt: SentDt || new Date().toISOString(),
        };

        const result = await r.db('test_db').table('messages')
            .insert(newMessage)
            .run(conn);

        res.status(201).json({ message: 'Message created successfully', data: result });
    } catch (err) {
        console.error('ERROR: Error posting message:', err.message);
        return res.status(500).send('Error posting message: ' + err.message);
    }
});

// Post a New Post
app.post('/api/posts', authenticate, async (req, res) => {
    const { UserID, Content, MediaType, MediaURL, Timestamp } = req.body;

    try {
        const newPost = {
            UserID,
            Content,
            MediaType,
            MediaURL,
            Timestamp: Timestamp || new Date().toISOString(),
            CommentsCount: 0,
            LikesCount: 0,
            SharesCount: 0,
            ViewCount: 0,
        };

        const result = await r.db('test_db').table('posts')
            .insert(newPost)
            .run(conn);

        res.status(201).json({ message: 'Post created successfully', data: result });
    } catch (err) {
        console.error('ERROR: Error posting post:', err.message);
        return res.status(500).send('Error posting post: ' + err.message);
    }
});

// 404 Error Handler for unknown URLs
app.use((req, res) => {
    res.status(404).json({
        error: {
            message: `Cannot GET ${req.originalUrl}`,
            status: 404
        }
    });
});

// Start the server and connect to the database
const startServer = async () => {
    await connectToDatabase();
    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
};

startServer();
