export {};

/**
 * API 管理平台认证客户端（认证中心模式）
 * 登录凭证完全由平台签发与校验，本系统不再维护本地账号体系。
 * 实现依据《外部系统接入指南》方式二：
 * - 登录：账号密码转发平台 /api/v1/auth/token 换取时效 token（有效期 2 小时）
 * - 校验：调用平台 /api/v1/auth/introspect，带短缓存（有效 30 秒 / 无效 5 秒）
 */

const axios = require('axios').default;
const { createModuleLogger } = require('./logger');

const logger = createModuleLogger('platform-auth');

// 默认平台地址，可通过环境变量 PLATFORM_BASE 覆盖
const DEFAULT_PLATFORM_BASE = 'http://api.bay666.top';

// introspect 校验结果缓存 TTL：有效 30 秒、无效 5 秒，降低对平台的调用量
const VALID_CACHE_TTL_MS = 30 * 1000;
const INVALID_CACHE_TTL_MS = 5 * 1000;
// 对平台的请求超时时间
const REQUEST_TIMEOUT_MS = 10 * 1000;

const introspectCache = new Map<string, { active: boolean; data: any; cachedAt: number }>();

function getPlatformBase(): string {
    return String(process.env.PLATFORM_BASE || DEFAULT_PLATFORM_BASE).trim().replace(/\/+$/, '');
}

/**
 * 用账号密码向平台换取时效 token
 * 成功返回 { ok, token, account, systemName, expiresAt }，失败返回 { ok: false, message }
 */
async function exchangeToken(account: string, password: string): Promise<any> {
    try {
        const response = await axios.post(`${getPlatformBase()}/api/v1/auth/token`, {
            grant_type: 'password',
            account,
            password,
        }, {
            timeout: REQUEST_TIMEOUT_MS,
            headers: { 'Content-Type': 'application/json' },
        });
        const body = response.data || {};
        // 判断成功需同时看 HTTP 2xx 与业务码 code === 200（指南 1.2 节约定）
        if (response.status >= 200 && response.status < 300 && body.code === 200 && body.data?.access_token) {
            return {
                ok: true,
                token: String(body.data.access_token),
                account: String(body.data.account || account),
                systemName: String(body.data.system_name || ''),
                // expires_at 为平台本地时间字符串，这里用 expires_in 兜底计算过期时间
                expiresAt: Date.now() + Number(body.data.expires_in || 7200) * 1000,
            };
        }
        return { ok: false, message: String(body.message || '认证失败：凭据无效、账号被禁用或已过期') };
    } catch (error: any) {
        // 平台对 401 故意返回模糊信息，原样透传给前端
        const status = Number(error?.response?.status) || 0;
        if (status === 401) {
            const message = String(error?.response?.data?.message || '');
            return { ok: false, message: message || '认证失败：凭据无效、账号被禁用或已过期' };
        }
        logger.warn('平台凭证签发请求失败', { status, message: error?.message });
        return { ok: false, message: '认证服务暂不可用，请稍后重试' };
    }
}

/**
 * 向平台校验 token 是否有效（带短缓存）
 * 平台不可达时抛出异常，由调用方做 503 降级，避免未认证流量穿透
 */
async function introspectToken(token: string): Promise<{
    active: boolean;
    account?: string;
    systemName?: string;
    accountId?: number;
}> {
    const cached = introspectCache.get(token);
    if (cached) {
        const ttl = cached.active ? VALID_CACHE_TTL_MS : INVALID_CACHE_TTL_MS;
        if (Date.now() - cached.cachedAt < ttl) {
            return { active: cached.active, ...cached.data };
        }
        introspectCache.delete(token);
    }

    const response = await axios.post(`${getPlatformBase()}/api/v1/auth/introspect`, { token }, {
        timeout: REQUEST_TIMEOUT_MS,
        headers: { 'Content-Type': 'application/json' },
    });
    const body = response.data || {};
    if (response.status >= 400 || body.code !== 200) {
        throw new Error(`平台校验接口异常 [${response.status}]`);
    }

    // token 不存在/过期/被撤销/账号失效时平台统一返回 active=false
    const active = body.data?.active === true;
    const data = active ? {
        account: String(body.data.account || ''),
        systemName: String(body.data.system_name || ''),
        accountId: Number(body.data.account_id) || 0,
    } : {};
    introspectCache.set(token, { active, data, cachedAt: Date.now() });
    return { active, ...data };
}

/**
 * 登出时清除本地校验缓存
 * 平台侧 token 由其自然过期（2 小时）或由平台管理员撤销，本系统无需也无法主动吊销
 */
function evictToken(token: string): void {
    if (token) introspectCache.delete(token);
}

module.exports = { getPlatformBase, exchangeToken, introspectToken, evictToken };
