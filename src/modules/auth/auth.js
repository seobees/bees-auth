const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const { compareSync } = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { find } = require('../../services/user');
const config = require('../../config');

const router = new Router();

router.post('/login', bodyParser(), async ctx => {
  const { login, password } = ctx.request.body;
  const user = await find({ login });
  if (!user || !compareSync(password, user.password)) {
    const error = new Error();
    error.status = 403;
    throw error;
  }
  const refreshToken = uuidv4();
  ctx.body = {
    token: jwt.sign({ id: user.id }, config.secret),
    refreshToken
  }
  // ctx.body.token = '';
  // ctx.body.refreshToken = '';
});

module.exports = router;
