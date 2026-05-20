import { Google, GitHub } from 'arctic';

const APP_URL = process.env.APP_URL || 'https://ariatrust.org';

export const googleOAuth = new Google(
  process.env.GOOGLE_CLIENT_ID || '',
  process.env.GOOGLE_CLIENT_SECRET || '',
  `${APP_URL}/v1/auth/google/callback`
);

export const githubOAuth = new GitHub(
  process.env.GITHUB_CLIENT_ID || '',
  process.env.GITHUB_CLIENT_SECRET || '',
  null
);

export function isOAuthEnabled(): { google: boolean; github: boolean } {
  return {
    google: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
    github: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET)
  };
}
