import request from 'supertest';
import app from '../src/index';

describe('Auth API', () => {
    it('should register a user', async () => {
        const res = await request(app)
            .post('/register')
            .send({ username: 'test', password: 'password123' });
        expect(res.status).toBe(201);
    });

    it('should login and return token', async () => {
        const res = await request(app)
            .post('/login')
            .send({ username: 'test', password: 'password123' });
        expect(res.status).toBe(200);
        expect(res.body.token).toBeDefined();
    });
});
