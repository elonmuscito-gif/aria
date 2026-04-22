import { Resend } from 'resend';

const FROM_EMAIL = 'ARIA <onboarding@resend.dev>';

console.log('[email] RESEND_API_KEY exists:', !!process.env.RESEND_API_KEY);
console.log('[email] APP_URL:', process.env.APP_URL);

// Lazy init — only construct when RESEND_API_KEY is present to avoid
// crashing at startup in local/dev environments.
function getResend(): Resend {
  const key = process.env.RESEND_API_KEY;
  if (!key) throw new Error('RESEND_API_KEY environment variable is not set');
  return new Resend(key);
}

export async function sendConfirmationEmail(
  email: string,
  name: string,
  token: string
): Promise<void> {
  const confirmUrl = `${process.env.APP_URL}/v1/auth/confirm?token=${token}`;

  const response = await getResend().emails.send({
    from: FROM_EMAIL,
    to: email,
    subject: 'Confirm your ARIA account',
    html: `
      <div style="font-family:system-ui;max-width:480px;margin:0 auto;padding:32px">
        <h1 style="font-size:24px;font-weight:700;margin-bottom:8px">Welcome to ARIA</h1>
        <p style="color:#666;margin-bottom:24px">Hi ${name}, confirm your email to get started.</p>
        <a href="${confirmUrl}"
           style="display:inline-block;background:#0a0a0a;color:#fff;
                  padding:12px 24px;border-radius:4px;text-decoration:none;
                  font-weight:500">
          Confirm Email
        </a>
        <p style="color:#999;font-size:12px;margin-top:24px">
          This link expires in 24 hours. If you did not create an ARIA account, ignore this email.
        </p>
      </div>
    `
  });
  console.log('[email] Resend response:', JSON.stringify(response));
}

export async function sendVerificationCode(
  email: string,
  code: string
): Promise<void> {
  const response = await getResend().emails.send({
    from: FROM_EMAIL,
    to: email,
    subject: `Your ARIA verification code: ${code}`,
    html: `
      <div style="font-family:system-ui;max-width:480px;margin:0 auto;padding:32px">
        <h1 style="font-size:24px;font-weight:700;margin-bottom:8px">Verification Code</h1>
        <p style="color:#666;margin-bottom:24px">Use this code to sign in to ARIA:</p>
        <div style="font-size:40px;font-weight:700;letter-spacing:8px;
                    text-align:center;padding:24px;background:#f5f5f5;
                    border-radius:8px;margin-bottom:24px">
          ${code}
        </div>
        <p style="color:#999;font-size:12px">
          This code expires in 10 minutes. Do not share it with anyone.
        </p>
      </div>
    `
  });
  console.log('[email] Resend response:', JSON.stringify(response));
}
