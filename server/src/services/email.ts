import { Resend } from 'resend';

const FROM_EMAIL = 'ARIA <noreply@ariatrust.org>';

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

export async function sendGateRequestEmail(
  ownerEmail: string,
  agentName: string,
  action: string,
  requestId: string,
  timeoutMinutes: number
): Promise<void> {
  const approveUrl =
    `${process.env.APP_URL}/v1/gate/approve/${requestId}`;
  const denyUrl =
    `${process.env.APP_URL}/v1/gate/deny/${requestId}`;
  const dashboardUrl =
    `${process.env.APP_URL}/app`;

  await getResend().emails.send({
    from: 'ARIA Gate <noreply@ariatrust.org>',
    to: ownerEmail,
    subject: `ARIA Gate: Action requires your approval`,
    html: `
      <div style="font-family:system-ui;max-width:600px;
                  margin:0 auto;padding:32px;
                  background:#04060d;color:#f8f4ee">
        <h1 style="color:#c9a84c;font-size:24px;
                   margin-bottom:8px">ARIA Gate</h1>
        <p style="color:rgba(248,244,238,0.6);
                  margin-bottom:32px">
          Action approval required
        </p>

        <div style="background:#07090f;border:1px solid
                    rgba(255,255,255,0.1);border-left:3px solid
                    #c9a84c;border-radius:8px;padding:24px;
                    margin-bottom:32px">
          <p style="margin:0 0 8px;font-size:13px;
                    color:rgba(248,244,238,0.5)">AGENT</p>
          <p style="margin:0 0 20px;font-size:18px;
                    font-weight:600">${agentName}</p>

          <p style="margin:0 0 8px;font-size:13px;
                    color:rgba(248,244,238,0.5)">
            REQUESTED ACTION
          </p>
          <p style="margin:0 0 20px;font-size:18px;
                    font-weight:600;color:#e8c87a;
                    font-family:monospace">${action}</p>

          <p style="margin:0;font-size:13px;
                    color:rgba(248,244,238,0.5)">
            This request expires in ${timeoutMinutes} minutes.
            If no action is taken, the request will be
            automatically denied.
          </p>
        </div>

        <div style="display:flex;gap:12px;margin-bottom:32px">
          <a href="${approveUrl}"
             style="flex:1;display:block;text-align:center;
                    padding:14px;background:#28c841;
                    color:#04060d;text-decoration:none;
                    border-radius:6px;font-weight:600;
                    font-size:15px">
            Approve
          </a>
          <a href="${denyUrl}"
             style="flex:1;display:block;text-align:center;
                    padding:14px;background:#c94c4c;
                    color:#f8f4ee;text-decoration:none;
                    border-radius:6px;font-weight:600;
                    font-size:15px">
            Deny
          </a>
        </div>

        <p style="font-size:13px;
                  color:rgba(248,244,238,0.35);
                  text-align:center">
          You can also manage this request in your
          <a href="${dashboardUrl}"
             style="color:#c9a84c">ARIA Dashboard</a>
        </p>
      </div>
    `
  });
}
