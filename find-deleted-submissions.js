// Diagnostic script to find traces of deleted submissions for Quiz 4
// This checks various sources that might have recorded who submitted

import pg from 'pg';
import dotenv from 'dotenv';

const { Pool } = pg;
dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function findDeletedSubmissions(quizId) {
  try {
    console.log(`\n=== Searching for traces of deleted submissions for Quiz ${quizId} ===\n`);
    
    // 1. Check if quiz 4 has a freeze_at timestamp - submissions would have been before that
    const quiz = await pool.query('SELECT id, title, unlock_at, freeze_at FROM quizzes WHERE id=$1', [quizId]);
    if (quiz.rows.length === 0) {
      console.log('❌ Quiz not found');
      return;
    }
    
    const quizData = quiz.rows[0];
    console.log(`Quiz: ${quizData.title || `Quiz #${quizId}`}`);
    console.log(`Unlocked: ${quizData.unlock_at}`);
    console.log(`Freeze at: ${quizData.freeze_at}`);
    console.log('');
    
    // 2. Check for any players who have OTHER quiz submissions around the same time
    // This might indicate they were active and likely submitted quiz 4
    const freezeDate = new Date(quizData.freeze_at);
    const windowStart = new Date(freezeDate.getTime() - 48 * 60 * 60 * 1000); // 48 hours before freeze
    const windowEnd = new Date(freezeDate.getTime() + 24 * 60 * 60 * 1000); // 24 hours after freeze
    
    console.log('2. Checking for players who submitted OTHER quizzes around the same time...');
    const activePlayers = await pool.query(`
      SELECT DISTINCT r.user_email, p.username, COUNT(DISTINCT r.quiz_id) as quiz_count
      FROM responses r
      LEFT JOIN players p ON p.email = r.user_email
      WHERE r.submitted_at >= $1 AND r.submitted_at <= $2
        AND r.quiz_id != $3
      GROUP BY r.user_email, p.username
      ORDER BY quiz_count DESC
    `, [windowStart, windowEnd, quizId]);
    
    console.log(`Found ${activePlayers.rows.length} players who were active during that time window:`);
    activePlayers.rows.forEach(p => {
      console.log(`  - ${p.username || p.user_email} (submitted ${p.quiz_count} other quiz(zes) during that window)`);
    });
    console.log('');
    
    // 3. Check for any responses that might have been created but not submitted
    // (These wouldn't have been deleted because they don't reference questions)
    console.log('3. Checking for any orphaned response records...');
    const orphaned = await pool.query(`
      SELECT COUNT(*) as count FROM responses 
      WHERE quiz_id = $1 AND question_id IS NULL
    `, [quizId]);
    console.log(`Orphaned responses (no question_id): ${orphaned.rows[0].count}`);
    console.log('');
    
    // 4. Check player activity - who has submitted to quizzes before/after quiz 4
    console.log('4. Checking player submission patterns...');
    const quizIds = await pool.query(`
      SELECT id, title, unlock_at FROM quizzes 
      WHERE unlock_at >= (SELECT unlock_at FROM quizzes WHERE id=$1) - INTERVAL '7 days'
        AND unlock_at <= (SELECT unlock_at FROM quizzes WHERE id=$1) + INTERVAL '7 days'
      ORDER BY unlock_at
    `, [quizId]);
    
    const nearbyQuizzes = quizIds.rows;
    console.log(`Found ${nearbyQuizzes.length} quizzes within 7 days of quiz ${quizId}:`);
    nearbyQuizzes.forEach(q => {
      console.log(`  Quiz ${q.id}: ${q.title || 'Untitled'} (unlocked ${q.unlock_at})`);
    });
    console.log('');
    
    // Get players who submitted to nearby quizzes
    const nearbyQuizIds = nearbyQuizzes.map(q => q.id);
    if (nearbyQuizIds.length > 0) {
      const playersNearby = await pool.query(`
        SELECT DISTINCT r.user_email, p.username, 
               COUNT(DISTINCT CASE WHEN r.quiz_id = $1 THEN r.quiz_id END) as submitted_quiz4,
               COUNT(DISTINCT CASE WHEN r.quiz_id != $1 THEN r.quiz_id END) as submitted_others
        FROM responses r
        LEFT JOIN players p ON p.email = r.user_email
        WHERE r.quiz_id = ANY($2::int[]) AND r.submitted_at IS NOT NULL
        GROUP BY r.user_email, p.username
        ORDER BY submitted_others DESC
      `, [quizId, nearbyQuizIds]);
      
      console.log(`Players who submitted nearby quizzes:`);
      const likelySubmitters = playersNearby.rows.filter(p => {
        const quiz4Count = parseInt(p.submitted_quiz4 || '0');
        const othersCount = parseInt(p.submitted_others || '0');
        return quiz4Count === 0 && othersCount > 0;
      });
      console.log(`\n⚠️ LIKELY SUBMITTERS (submitted nearby quizzes but NOT quiz ${quizId}):`);
      likelySubmitters.forEach(p => {
        console.log(`  - ${p.username || p.user_email} (submitted ${p.submitted_others} nearby quiz(zes))`);
      });
      
      if (likelySubmitters.length === 0) {
        console.log('  (None found - all players who submitted nearby quizzes also have responses for quiz 4)');
      }
      
      // Also show ALL players who submitted nearby quizzes for reference
      console.log(`\n📊 ALL players who submitted nearby quizzes (for reference):`);
      playersNearby.rows.forEach(p => {
        const quiz4Count = parseInt(p.submitted_quiz4 || '0');
        const othersCount = parseInt(p.submitted_others || '0');
        const status = quiz4Count > 0 ? '✓ Has quiz 4' : '❌ Missing quiz 4';
        console.log(`  - ${p.username || p.user_email}: ${status} (${othersCount} other quizzes)`);
      });
    }
    
    // 5. Check application logs if available
    console.log('\n5. Application logs:');
    console.log('   Check your server logs for:');
    console.log(`   - POST requests to /quiz/${quizId}/submit`);
    console.log(`   - [gradeQuiz] logs for quiz ${quizId}`);
    console.log(`   - Any errors around the time you edited question 10`);
    
    // 6. Check if there are any database query logs
    console.log('\n6. Database query logs:');
    console.log('   If PostgreSQL query logging is enabled, check for:');
    console.log(`   - DELETE FROM questions WHERE quiz_id = ${quizId}`);
    console.log(`   - CASCADE DELETE operations around that time`);
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await pool.end();
  }
}

const quizId = process.argv[2] || 4;
findDeletedSubmissions(Number(quizId));

