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
    origin: 'http://localhost:3001', // Adjust this to your frontend URL
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

const verifyToken = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).send('Authorization token is required.');
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.user = decoded; // Attach the decoded token to the request object
        next(); // Proceed to the next middleware or route handler
    } catch (err) {
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).send('Invalid token.'); // User is not authenticated
        } else if (err.name === 'TokenExpiredError') {
            return res.status(401).send('Token has expired.'); // User is not authenticated
        } else {
            console.error('ERROR: Token verification error:', err.message);
            return res.status(500).send('Error verifying token: ' + err.message);
        }
    }
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
app.post('/api/register', [
    body('username')
        .isLength({ min: 5 }).withMessage('Username must be at least 5 characters long')
        .isAlphanumeric().withMessage('Username must be alphanumeric'),
    body('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
        .notEmpty().withMessage('Group ID is required'),
    body('picture')
        .optional()
        .isString().withMessage('Picture must be a base64 string')
        .matches(/^data:image\/[a-zA-Z]+;base64,/).withMessage('Picture must be a valid base64 image')
], async (req, res) => {
    const errors = validationResult(req);
    const groupId = "100" // registration from page for default user
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, picture } = req.body;

    // Check if the user already exists
    const existingUserCursor = await r.table('users').filter({ username }).run(conn);
    const existingUsers = await existingUserCursor.toArray();

    if (existingUsers.length > 0) {
        return res.status(400).json({ error: 'User already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await r.table('users').insert({ username, password: hashedPassword, groupId, picture }).run(conn);
        res.status(201).json({ message: 'User registered successfully.' });
    } catch (err) {
        return res.status(500).json({ error: 'Error registering user: ' + err.message });
    }
});


// User Login Route with Basic Auth
app.post('/api/login', async (req, res) => {
    // Check for Authorization header
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        console.log('ERROR: Authorization header is required.');
        return res.status(401).send('Authorization header is required.');
    }

    // Decode the credentials from the Authorization header
    const base64Credentials = authHeader.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');

    // Validate username and password lengths
    if (username.length < 5) {
        return res.status(400).json({ errors: [{ msg: 'Username must be at least 5 characters long' }] });
    }
    if (password.length < 8) {
        return res.status(400).json({ errors: [{ msg: 'Password must be at least 8 characters long' }] });
    }

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
        const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, { expiresIn: '1h' });
        console.log('SUCCESS: User logged in successfully:', username);

        // Return token, user ID, and picture
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
        // Fetch the user information based on userId
        const userCursor = await r.table('users').get(userId).run(conn);
        const user = await userCursor;

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Fetch posts created by the user
        const postsCursor = await r.table('posts')
            .filter({ UserID: userId }) // Filter posts created by the user
            .orderBy(r.desc('Timestamp')).limit(50) // Order by timestamp descending
            .run(conn);

        const posts = await postsCursor.toArray();

        // Create the response object
        const response = {
            userInfo: {
                username: user.username, // Add username
                picture: user.picture, // Add picture
            },
            posts: posts.map(post => ({
                CommentsCount: post.CommentsCount,
                Content: post.Content,
                LikesCount: post.LikesCount,
                MediaType: post.MediaType,
                MediaURL: post.MediaURL,
                PostID: post.PostID,
                SharesCount: post.SharesCount,
                Timestamp: post.Timestamp,
                UserID: post.UserID,
                ViewCount: post.ViewCount,
                id: post.id, // Assuming 'id' is a field in your posts table
            })),
        };

        res.json(response); // Return the combined object
    } catch (err) {
        console.error('ERROR: Error retrieving posts:', err.message);
        return res.status(500).send('Error retrieving posts: ' + err.message);
    }
});


app.delete('/api/:id/posts/:postId', authenticate, checkResourceAccess, async (req, res) => {
    const { id: userId, postId } = req.params;

    try {
        // Fetch the post directly into the post variable
        const post = await r.table('posts').get(postId).run(conn);

        if (!post) {
            return res.status(404).send('Post not found');
        }

        console.log('Fetched post:', post); // Debugging log

        // Check if the post belongs to the user
        if (post.UserID !== userId) {
            return res.status(403).send('You are not authorized to delete this post');
        }

        // Delete the post
        await r.table('posts').get(postId).delete().run(conn);

        res.send('Post deleted successfully');
    } catch (err) {
        console.error('ERROR: Error deleting post:', err.message);
        return res.status(500).send('Error deleting post: ' + err.message);
    }
});


// Post a New Message
app.post('/api/messages', verifyToken, async (req, res) => {
    const { ToUID, MessageText, SentDt } = req.body;
    const FROMUID = req.user.id; // Access the user ID from the request object

    const newMessage = {
        FROMUID,
        ToUID,
        MessageText,
        ReadStatus: 'Unread',
        SentDt: SentDt || new Date().toISOString(),
    };

    try {
        const result = await r.db('test_db').table('messages')
            .insert(newMessage)
            .run(conn);

        res.status(201).json({ message: 'Message created successfully', data: result });
    } catch (err) {
        console.error('ERROR: Error sending message:', err.message);
        return res.status(500).send('Error sending message: ' + err.message);
    }
});

// Post a New Post
app.post('/api/posts', verifyToken, async (req, res) => {
    const { Content, MediaType, MediaURL, Timestamp } = req.body;
    const UserID = req.user.id; // Access the user ID from the request object

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

    try {
        const result = await r.db('test_db').table('posts')
            .insert(newPost)
            .run(conn);

        res.status(201).json({ message: 'Post created successfully', data: result });
    } catch (err) {
        console.error('ERROR: Error sending post:', err.message);
        return res.status(500).send('Error sending post: ' + err.message);
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await r.db('test_db').table('posts')
            .orderBy(r.desc('Timestamp')) // Sort by Timestamp in descending order
            .limit(10) // Limit to the last 10 posts
            .run(conn);

        const postsArray = await posts.toArray(); // Convert cursor to array

        res.status(200).json(postsArray);
    } catch (err) {
        console.error('ERROR: Error fetching posts:', err.message);
        return res.status(500).send('Error fetching posts: ' + err.message);
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
