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

export async function sendPasswordResetEmail(
  to: string,
  resetUrl: string
): Promise<void> {
  if (!process.env.RESEND_API_KEY) {
    console.log(`[email] Password reset link for ${to}: ${resetUrl}`);
    return;
  }

  await getResend().emails.send({
    from: FROM_EMAIL,
    to,
    subject: 'Reset your ARIA password',
    html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: 'IBM Plex Mono', monospace, sans-serif;
      background: #030507;
      color: #f0ece4;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 480px;
      margin: 0 auto;
      background: #070b10;
      border: 1px solid rgba(212,168,67,0.2);
      border-top: 3px solid #d4a843;
      border-radius: 8px;
      padding: 40px;
    }
    .logo {
      font-size: 24px;
      font-weight: 700;
      color: #d4a843;
      letter-spacing: 4px;
      margin-bottom: 32px;
    }
    h1 { font-size: 18px; color: #f0ece4; margin-bottom: 16px; }
    p { color: rgba(240,236,228,0.65); line-height: 1.6; margin-bottom: 24px; font-size: 14px; }
    .button {
      display: inline-block;
      padding: 14px 28px;
      background: #d4a843;
      color: #030507;
      text-decoration: none;
      border-radius: 4px;
      font-weight: 600;
      font-size: 14px;
      margin-bottom: 24px;
    }
    .url { font-size: 11px; color: rgba(240,236,228,0.35); word-break: break-all; margin-bottom: 24px; }
    .footer {
      font-size: 11px;
      color: rgba(240,236,228,0.3);
      border-top: 1px solid rgba(255,255,255,0.06);
      padding-top: 20px;
      margin-top: 8px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">ARIA</div>
    <h1>Reset your password</h1>
    <p>
      You requested a password reset for your ARIA account.
      Click the button below to set a new password.
      This link expires in 1 hour.
    </p>
    <a href="${resetUrl}" class="button">Reset Password</a>
    <p class="url">Or copy this link:<br>${resetUrl}</p>
    <p>
      If you did not request this reset, you can safely ignore this email.
      Your password will not change.
    </p>
    <div class="footer">
      ARIA · ariatrust.org<br>
      This is an automated message — do not reply.
    </div>
  </div>
</body>
</html>
    `
  });
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
    `${process.env.APP_URL}/v1/gate/deny-page/${requestId}`;
  const dashboardUrl =
    `${process.env.APP_URL}/app`;

  if (!process.env.RESEND_API_KEY) {
    console.log(
      `[gate] Email not configured. Gate request ${requestId} ` +
      `for ${agentName} → ${action}`
    );
    console.log(`[gate] Approve: ${approveUrl}`);
    console.log(`[gate] Deny: ${denyUrl}`);
    return;
  }

  await getResend().emails.send({
    from: 'ARIA Gate <noreply@ariatrust.org>',
    to: ownerEmail,
    subject: `Action Required: ${agentName} wants to execute ${action}`,
    html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: 'IBM Plex Mono', monospace, sans-serif;
      background: #030507;
      color: #f0ece4;
      margin: 0;
      padding: 40px 20px;
    }
    .container {
      max-width: 520px;
      margin: 0 auto;
      background: #070b10;
      border: 1px solid rgba(212,168,67,0.2);
      border-top: 3px solid #c9a84c;
      border-radius: 8px;
      padding: 40px;
    }
    .logo {
      font-size: 20px;
      font-weight: 700;
      color: #d4a843;
      letter-spacing: 4px;
      margin-bottom: 8px;
    }
    .label {
      font-size: 10px;
      letter-spacing: 2px;
      color: rgba(240,236,228,0.4);
      text-transform: uppercase;
      margin-bottom: 32px;
    }
    h1 {
      font-size: 16px;
      color: #f0ece4;
      margin-bottom: 8px;
    }
    .agent-box {
      background: #04060d;
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 6px;
      padding: 20px;
      margin: 24px 0;
    }
    .field {
      margin-bottom: 12px;
    }
    .field-label {
      font-size: 10px;
      color: rgba(240,236,228,0.4);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 4px;
    }
    .field-value {
      font-size: 14px;
      color: #f0ece4;
      font-family: monospace;
    }
    .action-value {
      color: #e8c87a;
      font-size: 15px;
      font-weight: 600;
    }
    .buttons {
      display: flex;
      gap: 12px;
      margin: 28px 0;
    }
    .btn-approve {
      flex: 1;
      display: inline-block;
      padding: 14px 20px;
      background: #28c841;
      color: #030507;
      text-decoration: none;
      border-radius: 5px;
      font-weight: 700;
      font-size: 14px;
      text-align: center;
    }
    .btn-deny {
      flex: 1;
      display: inline-block;
      padding: 14px 20px;
      background: transparent;
      color: #c94c4c;
      border: 1px solid #c94c4c;
      text-decoration: none;
      border-radius: 5px;
      font-weight: 700;
      font-size: 14px;
      text-align: center;
    }
    .timeout {
      font-size: 12px;
      color: rgba(240,236,228,0.4);
      margin-bottom: 24px;
    }
    .footer {
      font-size: 11px;
      color: rgba(240,236,228,0.3);
      border-top: 1px solid rgba(255,255,255,0.06);
      padding-top: 20px;
      margin-top: 8px;
    }
    a.dashboard {
      color: #c9a84c;
      text-decoration: none;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">ARIA</div>
    <div class="label">Gate — Approval Required</div>

    <h1>An agent wants to execute a critical action</h1>
    <p style="color:rgba(240,236,228,0.6);font-size:14px;
               line-height:1.6;margin-bottom:0">
      Your agent is requesting permission before proceeding.
      Review the action below and approve or deny.
    </p>

    <div class="agent-box">
      <div class="field">
        <div class="field-label">Agent</div>
        <div class="field-value">${agentName}</div>
      </div>
      <div class="field">
        <div class="field-label">Action</div>
        <div class="field-value action-value">${action}</div>
      </div>
      <div class="field" style="margin-bottom:0">
        <div class="field-label">Request ID</div>
        <div class="field-value"
             style="font-size:11px;color:rgba(240,236,228,0.4)">
          ${requestId}
        </div>
      </div>
    </div>

    <div class="timeout">
      This request expires in ${timeoutMinutes} minutes.
      No response = automatically denied.
    </div>

    <div class="buttons">
      <a href="${approveUrl}" class="btn-approve">
        Approve
      </a>
      <a href="${denyUrl}" class="btn-deny">
        Deny
      </a>
    </div>

    <p style="font-size:12px;color:rgba(240,236,228,0.4);
               text-align:center;margin-bottom:20px">
      Or manage this request in your
      <a href="${dashboardUrl}" class="dashboard">
        ARIA Dashboard
      </a>
    </p>

    <div class="footer">
      ARIA · ariatrust.org<br>
      You received this because you own an agent
      that requested approval.
    </div>
  </div>
</body>
</html>
    `
  });

  console.log(
    `[gate] Email sent to ${ownerEmail} for request ${requestId}`
  );
}
