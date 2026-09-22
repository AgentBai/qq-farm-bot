import type { Application, Request, Response } from 'express';
import type { AdminContext } from './context';
export {};

const { version } = require('../../../package.json');
const { getRuntimeConfig } = require('../../config/config');
const { getSchedulerRegistrySnapshot } = require('../../services/scheduler');
const { createModuleLogger } = require('../../services/logger');
const platformAuth = require('../../services/platform-auth');

const {
    getClientIp,
    createAuthRequired,
    getAccId,
    handleApiError,
} = require('./middleware');

const adminLogger = createModuleLogger('admin');

function mountAuthRoutes(app: Application, ctx: AdminContext): void {
    const authRequired = createAuthRequired(ctx);

    app.post('/api/login', async (req: Request, res: Response) => {
        const { username, password } = req.body || {};
        if (!username || !password) {
            return res.status(401).json({ ok: false, error: '请输入账号和密码' });
        }

        const clientIp = getClientIp(req);
        // 登录凭证由 API 管理平台统一签发，本地不再维护账号体系
        const result = await platformAuth.exchangeToken(String(username), String(password));
        if (!result.ok) {
            adminLogger.warn('登录失败', { username, ip: clientIp });
            return res.status(401).json({
                ok: false,
                error: result.message,
                errorType: 'invalid_credentials',
            });
        }

        adminLogger.info('平台认证登录成功', { username: result.account, ip: clientIp, systemName: result.systemName });
        return res.json({
            ok: true,
            data: {
                token: result.token,
                role: 'admin',
                user: { username: result.account },
                // 平台模式下密码在平台侧管理，不存在本地改密流程
                mustChangePassword: false,
            },
        });
    });

    app.post('/api/user/change-password', authRequired, (_req: Request, res: Response) => {
        // 平台认证模式下密码由 API 管理平台统一管理
        return res.status(400).json({ ok: false, error: '平台认证模式下请前往 API 管理平台修改密码' });
    });

    app.use('/api', (req: Request, res: Response, next: any) => {
        if (req.path === '/login' || req.path === '/game-version') return next();
        return authRequired(req, res, next);
    });

    app.get('/api/ping', (_req: Request, res: Response) => {
        res.json({ ok: true, data: { ok: true, uptime: process.uptime(), version } });
    });

    app.get('/api/game-version', (_req: Request, res: Response) => {
        res.json({ ok: true, clientVersion: getRuntimeConfig().clientVersion, botVersion: version });
    });

    app.get('/api/auth/validate', (_req: Request, res: Response) => {
        res.json({ ok: true, data: { valid: true } });
    });

    app.get('/api/scheduler', async (req: Request, res: Response) => {
        try {
            const id = getAccId(ctx, req);
            if (ctx.provider && typeof ctx.provider.getSchedulerStatus === 'function') {
                const data = await ctx.provider.getSchedulerStatus(id);
                return res.json({ ok: true, data });
            }
            return res.json({
                ok: true,
                data: {
                    runtime: getSchedulerRegistrySnapshot(),
                    worker: null,
                    workerError: 'DataProvider does not support scheduler status',
                },
            });
        } catch (e: any) {
            return handleApiError(res, e);
        }
    });

    app.post('/api/logout', (req: Request, res: Response) => {
        const token = (req as any).adminToken;
        // 清除本地校验缓存；平台侧 token 由其自然过期或由平台管理员撤销
        if (token) platformAuth.evictToken(token);
        if (ctx.io && token) {
            for (const socket of ctx.io.sockets.sockets.values()) {
                if (String((socket.data as any).adminToken || '') === String(token)) socket.disconnect(true);
            }
        }
        res.json({ ok: true });
    });

    app.get('/api/user/me', async (req: Request, res: Response) => {
        try {
            // 从平台校验结果中获取当前登录账号身份
            const caller = await platformAuth.introspectToken(String((req as any).adminToken || ''));
            if (!caller.active) {
                return res.status(401).json({ ok: false, error: '登录已过期，请重新登录' });
            }
            return res.json({
                ok: true,
                data: {
                    username: caller.account || 'platform-user',
                    role: 'admin',
                    mustChangePassword: false,
                    systemName: caller.systemName,
                },
            });
        } catch {
            return res.status(503).json({ ok: false, error: '认证服务暂不可用，请稍后重试' });
        }
    });
}

module.exports = { mountAuthRoutes };
