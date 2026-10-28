import { db } from '../src/services/db.js';

async function seed() {
  // eslint-disable-next-line no-console
  console.log('🌱 Seeding Link Lens educational content...');
  // Ensure seed data is inserted into Supabase if configured
  await db.seedInitialDataIfNeeded();
  const scenarios = await db.getScenarios();
  const quizzes = await db.getQuizzes();
  // eslint-disable-next-line no-console
  console.log(`✅ Loaded ${scenarios.length} educational scenarios.`);
  // eslint-disable-next-line no-console
  console.log(`✅ Loaded ${quizzes.length} educational quizzes.`);
  // eslint-disable-next-line no-console
  console.log('🎉 Seed complete.');
}

seed().catch(err => {
  // eslint-disable-next-line no-console
  console.error('Seed error:', err);
  process.exit(1);
});

