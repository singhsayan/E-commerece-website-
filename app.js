import express from 'express';
import bcrypt from 'bcrypt';
import pg from 'pg';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import session from 'express-session';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

// Middleware setup
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
    })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(passport.initialize());
app.use(passport.session());

// Database connection
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect().catch(err => console.error('Error connecting to the database:', err));

// Passport configuration
passport.use(
    new LocalStrategy(
        { usernameField: 'email' },
        async (email, password, done) => {
            try {
                const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
                let user = result.rows[0];

                if (!user) {
                    const hash = await bcrypt.hash(password, saltRounds);
                    const newUser = await db.query(
                        'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
                        [email, hash]
                    );
                    user = newUser.rows[0];
                } else {
                    const match = await bcrypt.compare(password, user.password);
                    if (!match) {
                        return done(null, false, { message: 'Incorrect password.' });
                    }
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }
    )
);

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "http://localhost:3000/auth/google/callback",
            userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.emails[0].value]);
                if (result.rows.length === 0) {
                    const newUser = await db.query(
                        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
                        [profile.emails[0].value, "google"]
                    );
                    return done(null, newUser.rows[0]);
                } else {
                    return done(null, result.rows[0]);
                }
            } catch (err) {
                return done(err);
            }
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.set('view engine', 'ejs'); // Assuming you are using EJS templates

// Routes
app.get('/', (req, res) => {
    res.render('home', { user: req.user });
});


app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});


app.get("/success", isAuthenticated, (req, res) => {
    res.render("success", { user: req.user });
});

app.get(
    "/auth/google",
    passport.authenticate("google", {
        scope: ["profile", "email"],
    })
);

app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
        successRedirect: "/items",
        failureRedirect: "/login",
    })
);

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "/items",
        failureRedirect: "/login",
    })
);

app.post("/register", async (req, res) => {
    const { username, email, phone_no, address, password } = req.body;

    try {
        const checkResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (checkResult.rows.length > 0) {
            return res.redirect("/login");
        }

        const hash = await bcrypt.hash(password, saltRounds);

        const result = await db.query(
            'INSERT INTO users (name, email, phone_no, address, password) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [username, email, phone_no, address, hash]
        );

        const newUser = result.rows[0];

        req.login(newUser, (err) => {
            if (err) {
                console.error("Login after registration failed", err);
                return res.redirect("/register");
            }
            res.redirect("/success");
        });
    } catch (error) {
        console.error("Error during registration:", error);
        res.redirect("/register");
    }
});

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

// Fetch items from an API
app.get("/items", async (req, res) => {
    try {
        const response = await fetch("https://fakestoreapi.com/products");
        const products = await response.json();
        res.render("items", { products, user: req.user });
    } catch (error) {
        console.error("Error fetching products:", error);
        res.status(500).send("Internal Server Error");
    }
});


// Add item to cart
app.post("/cart/add", async (req, res) => {
    const { product_id, amount, quantity } = req.body;
    const user_id = req.user.id;

    try {
        // Check if the product already exists in the products table
        let productResult = await db.query('SELECT * FROM products WHERE id = $1', [product_id]);

        // If the product does not exist, insert it into the products table
        if (productResult.rows.length === 0) {
            productResult = await db.query(
                'INSERT INTO products ( cost) VALUES ($1) RETURNING *',
                [ price]
            );
        }

        const product = productResult.rows[0];

        // Log values for debugging
        console.log(`Adding to cart: user_id=${user_id}, product_id=${product_id}, amount=${product.price}, quantity=${quantity}`);

        // Insert the item into the cart table
        await db.query('INSERT INTO cart (user_id, product_id, amount, quantity) VALUES ($1, $2, $3, $4)', [user_id, product_id, product.price, quantity]);

        res.status(200).json({ message: 'Item added to cart successfully' });
    } catch (error) {
        console.error("Error adding items to cart:", error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




// Update cart item quantity
app.post("/cart/update/:id", async (req, res) => {
    const cartItemID = req.params.id;
    const { quantity } = req.body;
    try {
        const result = await db.query(
            'UPDATE cart SET quantity = $1 WHERE id = $2 RETURNING *',
            [quantity, cartItemID]
        );
        const updatedCartItem = result.rows[0];
        res.json(updatedCartItem);
    } catch (error) {
        console.error('Error updating cart item quantity:', error);
        res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
});


// Route to fetch items in the cart
app.get("/cart", isAuthenticated, async (req, res) => {
    const user_id = req.user.id;

    try {
        const result = await db.query('SELECT * FROM cart WHERE user_id = $1', [user_id]);
        const cartItems = result.rows;

        // Calculate the total
        const total = cartItems.reduce((sum, item) => sum + (item.quantity * item.amount), 0);

        // Render the cart page with the fetched cart items and the total
        res.render("cart", { cartItems, total, user: req.user });
    } catch (error) {
        console.error("Error fetching cart items:", error);
        res.status(500).send("Internal Server Error");
    }
});





// Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.user });
});

// Route to handle logout
app.get('/logout', (req, res) => {
    req.logout(); // This logs the user out
    res.redirect('/'); // Redirect to the home page after logout
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
