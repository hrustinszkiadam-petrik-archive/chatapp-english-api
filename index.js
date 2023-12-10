import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import mysql from 'mysql';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import validator from 'validator';
import cookieParser from 'cookie-parser';
import { WebSocketServer } from 'ws';

dotenv.config();
const PORT = parseInt(process.env.PORT) || 3000;
const SALT = parseInt(process.env.SALT) || 10;

const db = mysql.createConnection({
	host: process.env.DB_HOST || 'localhost',
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD || '',
	database: process.env.DB_NAME,
});

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
	cors({
		credentials: true,
		methods: ['GET', 'POST', 'DELETE'],
		origin: 'https://chatapp-english.onrender.com',
	})
);
app.use(cookieParser());

db.connect((err) => {
	if (err) throw err;
	console.log('Connected to database');
});

app.get('/test', (req, res) => {
	res.json('test ok');
});

app.get('/user', (req, res) => {
	const { token } = req.cookies;
	if (!token) return res.status(401).json({ Error: 'No token found' });

	jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
		if (err) return res.status(401).json({ Error: 'Unauthorized' });
		const { id, username, email } = decoded;
		res.status(200).json({
			Success: 'User found',
			user: {
				id,
				username,
				email,
			},
		});
	});
});

const validateRegistration = (req, res, next) => {
	const { email, username, password } = req.body;
	if (!email || !username || !password) {
		return res.status(400).json({ Error: 'Missing fields' });
	}
	if (!validator.isEmail(email)) {
		return res.status(400).json({ Error: 'Invalid email' });
	}
	if (!validator.isAlphanumeric(username)) {
		return res.status(400).json({
			Error: 'Username cannot contain special characters or spaces',
		});
	}

	db.query('SELECT * FROM users WHERE email = ?', [email], (error, result) => {
		if (error) return res.status(400).json({ Error: 'Error checking email' });
		if (result.length > 0)
			return res.status(400).json({ Error: 'Email already registered' });
		db.query(
			'SELECT * FROM users WHERE username = ?',
			[username],
			(error, result) => {
				if (error)
					return res
						.status(400)
						.json({ Error: 'Error checking username' });
				if (result.length > 0)
					return res
						.status(400)
						.json({ Error: 'Username already registered' });
				next();
			}
		);
	});
};

app.post('/register', validateRegistration, async (req, res) => {
	const { email, username, password } = req.body;
	const hashedPassword = await bcrypt.hash(password.toString(), SALT);

	db.query(
		'INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
		[email, username, hashedPassword],
		(err, result) => {
			if (err)
				return res.status(400).json({ Error: 'Error creating new user' });
			db.query(
				'SELECT * FROM users WHERE email = ?',
				[email],
				(err, result) => {
					if (err)
						return res
							.status(400)
							.json({ Error: 'Error getting new user' });
					if (result) {
						const id = result[0].id;
						jwt.sign(
							{ id, username, email },
							process.env.JWT_SECRET,
							{ expiresIn: '3d' },
							(err, token) => {
								if (err)
									res.status(400).json({
										Error: 'Error signing token',
									});
								return res
									.cookie('token', token, {
										httpOnly: true,
										secure: true,
										sameSite: 'none',
									})
									.status(201)
									.json({ Success: 'User created' });
							}
						);
					}
				}
			);
		}
	);
});

const validateLogin = (req, res, next) => {
	const { account, password, isEmail } = req.body;
	if (!account || !password) {
		return res.status(400).json({ Error: 'Missing fields' });
	}
	if (isEmail && !validator.isEmail(account)) {
		return res.status(400).json({ Error: 'Invalid email' });
	}

	next();
};

app.post('/login', validateLogin, (req, res) => {
	const { account, password, isEmail } = req.body;
	const query = isEmail
		? 'SELECT * FROM users WHERE email = ?'
		: 'SELECT * FROM users WHERE username = ?';

	db.query(query, [account], (err, result) => {
		if (err) return res.status(400).json({ Error: 'Error logging in' });
		if (result.length === 0)
			return res.status(400).json({ Error: 'User not found' });

		const user = result[0];

		bcrypt.compare(password.toString(), user.password, (err, match) => {
			if (err) return res.status(400).json({ Error: 'Error logging in' });
			if (!match) return res.status(400).json({ Error: 'Invalid password' });

			const { id, username, email } = user;
			jwt.sign(
				{ id, username, email },
				process.env.JWT_SECRET,
				{ expiresIn: '3d' },
				(err, token) => {
					if (err) res.status(400).json({ Error: 'Error signing token' });
					return res
						.cookie('token', token, {
							httpOnly: true,
							secure: true,
							sameSite: 'none',
						})
						.status(200)
						.json({ Success: 'User logged in' });
				}
			);
		});
	});
});

app.delete('/logout', (req, res) => {
	if (!req.cookies.token)
		return res.status(400).json({ Error: 'User not logged in' });
	return res
		.cookie('token', '', {
			maxAge: '1',
			httpOnly: true,
			secure: true,
			sameSite: 'none',
		})
		.status(200)
		.json({ Success: 'User logged out' });
});

const server = app.listen(PORT, () =>
	console.log('API listening on port', PORT)
);

const uploadMessage = async (message, senderId, recipientId) => {
	return await new Promise((resolve, reject) => {
		try {
			db.query(
				'INSERT INTO messages (message, from_id, to_id) VALUES (?, ?, ?)',
				[message, senderId, recipientId],
				(err, result) => {
					if (err) throw err;
					resolve(result);
				}
			);
		} catch (err) {
			reject(err);
		}
	});
};

const getMessagesBetween = async (userId, recipientId) => {
	return await new Promise((resolve, reject) => {
		try {
			db.query(
				`SELECT * FROM messages WHERE (from_id = ${userId} AND to_id = ${recipientId}) OR (from_id = ${recipientId} AND to_id = ${userId}) ORDER BY id ASC`,
				(err, result) => {
					if (err) throw err;
					resolve(result);
				}
			);
		} catch (err) {
			reject(err);
		}
	});
};

const getConversations = async (userId) => {
	return await new Promise((resolve, reject) => {
		try {
			//get the users that the user has sent messages to or received messages from
			//the id's of the messages reference the users table
			db.query(
				`SELECT DISTINCT users.id, users.username FROM users INNER JOIN messages ON users.id = messages.from_id OR users.id = messages.to_id WHERE users.id != ${userId} AND (messages.from_id = ${userId} OR messages.to_id = ${userId})`,
				(err, result) => {
					if (err) throw err;
					resolve(result);
				}
			);
		} catch (err) {
			reject(err);
		}
	});
};

const wss = new WebSocketServer({ server });

wss.on('connection', async (connection, req) => {
	//* Get userId and username from token
	const cookies = req.headers.cookie;
	if (cookies) {
		const tokenString = cookies
			.split(';')
			.find((row) => row.startsWith('token='));
		if (tokenString) {
			const token = tokenString.split('=')[1];
			if (token) {
				jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
					if (err) throw err;
					const { id, username } = decoded;
					connection.userId = id;
					connection.username = username;
				});
			}
		}
	}

	//* Send online users to clients and the client's conversations

	try {
		const conversations = await getConversations(connection.userId);
		connection.send(
			JSON.stringify({
				conversations,
			})
		);
	} catch (err) {
		console.error(err);
	}

	[...wss.clients].forEach((client) => {
		client.send(
			JSON.stringify({
				online: [...wss.clients].map((client) => {
					return {
						userId: client.userId,
						username: client.username,
					};
				}),
			})
		);
	});

	connection.on('message', async (msg) => {
		const { message, recipientId, conversations } = JSON.parse(
			msg.toString()
		);
		if (message && recipientId) {
			try {
				await uploadMessage(message, connection.userId, recipientId);
			} catch (err) {
				console.error(err);
			}

			let messages = [];
			try {
				messages = await getMessagesBetween(connection.userId, recipientId);
			} catch (err) {
				console.error(err);
			}

			const latestMessage = messages[messages.length - 1];

			[...wss.clients]
				.filter(
					(client) =>
						client.userId === recipientId ||
						client.userId === connection.userId
				)
				.forEach((client) => {
					client.send(
						JSON.stringify({
							messageId: latestMessage.id,
							message: latestMessage.message,
							isMine: client.userId === connection.userId,
							senderId: latestMessage.from_id,
							recipientId,
						})
					);
				});
		} else if (!message && recipientId) {
			let messages = [];
			try {
				messages = await getMessagesBetween(connection.userId, recipientId);
			} catch (err) {
				console.error(err);
			}

			[...wss.clients]
				.filter((client) => client.userId === connection.userId)
				.forEach((client) => {
					client.send(
						JSON.stringify({
							messages: messages.map((message) => {
								return {
									messageId: message.id,
									message: message.message,
									isMine: message.from_id === connection.userId,
									senderId: message.from_id,
									recipientId: message.to_id,
								};
							}),
						})
					);
				});
		} else if (conversations) {
			try {
				const conversations = await getConversations(connection.userId);
				connection.send(
					JSON.stringify({
						conversations,
					})
				);
			} catch (err) {
				console.error(err);
			}
		}
	});
});
