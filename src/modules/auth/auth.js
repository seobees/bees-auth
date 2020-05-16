const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const { compareSync } = require('bcryptjs');
const jwt = require('jsonwebtoken');
const jwtMiddleware = require('koa-jwt');
const { v4: uuidv4 } = require('uuid');
const { find: findUser } = require('../../services/user');
const { find: findToken, create: saveToken, remove: removeToken } = require('../../services/refreshToken');
const config = require('../../config');

const router = new Router();

async function issueTokenPair(userId) {
  const newRefreshToken = uuidv4();
  await saveToken({ token: newRefreshToken, userId });
  return {
    token: jwt.sign({ id: userId }, config.secret),
    refreshToken: newRefreshToken
  }
}

router.post('/login', bodyParser(), async ctx => {
  const { login, password } = ctx.request.body;
  const user = await findUser({ login });
  if (!user || !compareSync(password, user.password)) {
    ctx.throw(403);
  }
  ctx.body = await issueTokenPair(user.id);
});

router.post('/refresh', bodyParser(), async ctx => {
  const { refreshToken } = ctx.request.body;
  const dbToken = await findToken({ token: refreshToken });
  if (!dbToken) {
    return;
  }
  await removeToken({ token: refreshToken });
  ctx.body = await issueTokenPair(dbToken.userId)
})

router.post('/logout', jwtMiddleware({ secret: config.secret }), async ctx => {
  const { id: userId } = ctx.state.user;
  await removeToken({ userId });
  ctx.body = { success: true };
});

module.exports = router;
