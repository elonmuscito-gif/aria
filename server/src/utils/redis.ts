import Redis from 'ioredis';

let redisClient: Redis | null = null;

export function getRedisClient(): Redis | null {
  if (!process.env.REDIS_URL) return null;

  if (!redisClient) {
    redisClient = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      enableOfflineQueue: false,
    });

    redisClient.on('error', (err) => {
      console.error('[redis] Connection error:',
        err instanceof Error ? err.message : 'Unknown error');
    });

    redisClient.on('connect', () => {
      console.log('[redis] Connected');
    });
  }

  return redisClient;
}
