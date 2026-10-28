import { db } from '../src/services/db.js';

async function main() {
  const args = process.argv.slice(2);
  const email = args[0] || 'admin@linklens.local';
  const password = args[1] || 'AdminSecurePass!2026';
  const displayName = args[2] || 'Lead Security Analyst';

  // eslint-disable-next-line no-console
  console.log(`🔐 Provisioning Administrator [${email}]...`);

  const existing = await db.getUserByEmail(email);
  if (existing) {
    await db.updateProfile(existing.id, { role: 'admin' }, true);
    // eslint-disable-next-line no-console
    console.log(`✅ Existing user '${email}' has been promoted to Administrator role.`);
  } else {
    const user = await db.createUser({
      email,
      password,
      displayName,
      role: 'admin',
    });
    // eslint-disable-next-line no-console
    console.log(`✅ New Administrator '${user.email}' created with ID: ${user.id}`);
  }
}

main().catch(err => {
  // eslint-disable-next-line no-console
  console.error('Provisioning error:', err.message);
  process.exit(1);
});

