import nodemailer from 'nodemailer';

const transport = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// small helper used by all mail sends
async function sendMail(to, subject, text, html) {
  try {
    const info = await transport.sendMail({
      from: `"GuardianLink" <${process.env.SMTP_USER}>`,
      to, subject, text, html
    });
    return info?.messageId;
  } catch (e) {
    console.error('❌ Mail send error:', e.message);
  }
}

export async function sendResetCode(to, code, ttlMin) {
  const subject = 'Your GuardianLink reset code';
  const text = `Your GuardianLink reset code is ${code}. It expires in ${ttlMin} minutes.`;
  const html = `<p>Your GuardianLink reset code is <b>${code}</b>.</p><p>Expires in ${ttlMin} minutes.</p>`;
  if (process.env.NODE_ENV !== 'production') {
    console.log(`🔐 DEV reset code for ${to}: ${code}`);
  }
  return sendMail(to, subject, text, html);
}

export async function verifyMailer() {
  await transport.verify();
  console.log('✅ SMTP ready: gmail');
}

export async function sendVerifyCode(to, code) {
  const subject = 'GuardianLink: Verify your email';
  const text = `Your GuardianLink verification code is ${code}. It expires in 10 minutes.`;
  const html = `<p>Your GuardianLink verification code is <b>${code}</b>.</p><p>It expires in 10 minutes.</p>`;

  // DEV mirror to VS Code terminal
  if (process.env.NODE_ENV !== 'production') {
    console.log(`✅ DEV verify code for ${to}: ${code}`);
  }

  // in dev, redirect all mails to your inbox
  const overrideTo = process.env.NODE_ENV === 'production'
    ? to
    : (process.env.DEV_MAIL_REDIRECT || to); // set DEV_MAIL_REDIRECT=liktong5662@gmail.com if you want
  return sendMail(overrideTo, subject, text, html);
}


export async function sendEmailVerification(to, token) {
  // if you later switch from code to link
  const url = `${process.env.CLIENT_VERIFY_URL}?email=${encodeURIComponent(to)}&token=${encodeURIComponent(token)}`;
  return sendMail(
    to,
    'Verify your GuardianLink email',
    `Tap this link to verify your account: ${url}`,
    `<p>Tap to verify your account:</p><p><a href="${url}">${url}</a></p><p>This link expires in 24 hours.</p>`
  );
}

// generic security alert mail (for intrusion events)
export async function sendSecurityAlertEmail(to, subject, message) {
  const text = message;
  const html = `<p>${message}</p><p>If this wasn't you, please review your GuardianLink security settings.</p>`;
  return sendMail(to, subject, text, html);
}


