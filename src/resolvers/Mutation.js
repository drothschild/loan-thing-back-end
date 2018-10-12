const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');

const mutations = {
    async signup(parents, args, ctx, info) {
        args.email = args.email.toLowerCase();
        if (!validator.isEmail(args.email)) {
            throw new Error('Invalid Email Address!');
        }
        if (!validator.isLength(args.password, { min: 8, max: undefined })) {
            throw new Error('Password must be at least 8 characters!');
        }
        // hash their password
        const password = await bcrypt.hash(args.password, 10);
        // create user in the database
        const user = await ctx.db.mutation.createUser(
            {
                data: {
                    ...args,
                    password,
                    permissions: { set: ['USER'] }
                }
            },
            info
        );
        // Create JWT Toek
        const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
        // set the jwt as a cookie
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
        });
        // finally user
        return user;
    },
    async login(parents, { email, password }, ctx, info) {
        // 1. check if there is a user
        // TODO: Make query on email or loginname
        const user = await ctx.db.query.user({ where: { email } });
        if (!user) {
            throw new Error(`No such user found for email ${email}`);
        }
        // 2. check if their password is correct
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            throw new Error('Invalid Password!');
        }
        // 3. generate token
        const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
        // set the jwt as a cookie
        // 4. set the cookie with the JWT TOken
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
        });
        // 5. return user
        return user;
    },
    async logout(parents, args, ctx, info) {
        ctx.response.clearCookie('token');
        return { message: 'Come back soon!' };
    }
};

module.exports = mutations;
