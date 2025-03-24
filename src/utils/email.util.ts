import * as nodemailer from 'nodemailer';

export async function sendOTPEmail(email: string, otp: string): Promise<void> {
  const transporter = nodemailer.createTransport({
    service: 'gmail',     
    auth: {
      user: 'shikharmpatel2004@gmail.com',
      pass: 'vqxt wsxl fgcr ksjt', 
    },
  });

  const mailOptions = {
    from: 'shikharmpatel2004@gmail.com',
    to: email,
    subject: 'Your OTP for Registration/Delete User',
    text: `Your OTP is ${otp}. It is valid for 60 seconds.`,
  };

  await transporter.sendMail(mailOptions);
}

