const bcrypt = require('bcryptjs');
const { forwardTo } = require('prisma-binding');
const jwt = require('jsonwebtoken');
const validator = require('validator');

const Query = {
    me(parent, args, ctx, info) {
        // Check if there is a current user id
        if (!ctx.request.userId) {
            return null;
        }
        return ctx.db.query.user({ where: { id: ctx.request.userId } }, info);
    }
};
