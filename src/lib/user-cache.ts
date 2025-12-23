/* eslint-disable @typescript-eslint/no-explicit-any */

// 用户信息缓存
interface CachedUserInfo {
  role: 'owner' | 'admin' | 'user';
  banned: boolean;
  tags?: string[];
  oidcSub?: string;
  enabledApis?: string[];
  created_at: number;
  cachedAt: number;
}

class UserInfoCache {
  private cache: Map<string, CachedUserInfo> = new Map();
  private readonly TTL = 6 * 60 * 60 * 1000; // 6小时过期

  get(username: string): CachedUserInfo | null {
    const cached = this.cache.get(username);
    if (!cached) return null;

    // 检查是否过期
    if (Date.now() - cached.cachedAt > this.TTL) {
      this.cache.delete(username);
      return null;
    }

    return cached;
  }

  set(username: string, userInfo: Omit<CachedUserInfo, 'cachedAt'>): void {
    this.cache.set(username, {
      ...userInfo,
      cachedAt: Date.now(),
    });
  }

  delete(username: string): void {
    this.cache.delete(username);
  }

  clear(): void {
    this.cache.clear();
  }

  // 清理过期的缓存
  cleanup(): void {
    const now = Date.now();
    const entries = Array.from(this.cache.entries());
    for (const [username, cached] of entries) {
      if (now - cached.cachedAt > this.TTL) {
        this.cache.delete(username);
      }
    }
  }
}

// 全局单例
const globalKey = Symbol.for('__MOONTV_USER_INFO_CACHE__');
let userInfoCache: UserInfoCache | undefined = (global as any)[globalKey];

if (!userInfoCache) {
  userInfoCache = new UserInfoCache();
  (global as any)[globalKey] = userInfoCache;

  // 每分钟清理一次过期缓存
  setInterval(() => {
    userInfoCache?.cleanup();
  }, 60 * 1000);
}

export { userInfoCache };
