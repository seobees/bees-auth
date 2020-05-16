const test = require('ava');
const agent = require('supertest-koa-agent');
const createApp = require('../src/app');

const app = agent(createApp());

test('User can successfully login', async t => {
  const res = await app.post('/auth/login').send({ login: 'user', password: 'user' });
  t.is(res.status, 200);
  t.truthy(typeof res.body.token === 'string');
  t.truthy(typeof res.body.refreshToken === 'string');
});

test('User gets 403 on invalid credentials', async t => {
  const res = await app.post('/auth/login').send({ login: 'INVALID', password: 'INVALID' });
  t.is(res.status, 403);
});

test.todo('User gets 401 on expired token');
test.todo('User can refresh access token using refresh token');
test.todo('User can use refresh token only once');
test.todo('Refresh tokens become invalid on logout');
test.todo('Multiple refresh tokens are valid');
