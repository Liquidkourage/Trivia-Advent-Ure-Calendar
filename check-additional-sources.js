// Check additional sources for deleted submissions
// 1. Session table (sessions expire after 30 days)
// 2. Server logs (if accessible)

import pg from 'pg';
import dotenv from 'dotenv';

const { Pool } = pg;
dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function checkAdditionalSources(quizId) {
  try {
    console.log(`\n=== Checking Additional Sources for Quiz ${quizId} ===\n`);
    
    // 1. Check session table (sessions expire after 30 days)
    console.log('1. Checking session table for active sessions...');
    try {
      // connect-pg-simple creates a table called 'session'
      const sessions = await pool.query(`
        SELECT sid, sess, expire 
        FROM session 
        WHERE expire > NOW()
        ORDER BY expire DESC
        LIMIT 100
      `);
      
      console.log(`Found ${sessions.rows.length} active sessions`);
      
      // Try to extract user emails from session data
      const userEmails = new Set();
      sessions.rows.forEach(row => {
        try {
          const sess = typeof row.sess === 'string' ? JSON.parse(row.sess) : row.sess;
          if (sess?.user?.email) {
            userEmails.add(sess.user.email.toLowerCase());
          }
        } catch (e) {
          // Session data might be encrypted or in different format
        }
      });
      
      if (userEmails.size > 0) {
        console.log(`\nFound ${userEmails.size} unique user emails in active sessions:`);
        Array.from(userEmails).forEach(email => console.log(`  - ${email}`));
      } else {
        console.log('  (Could not extract user emails from session data - may be encrypted)');
      }
      
      // Check if any sessions were active around quiz 4's submission window
      const quiz = await pool.query('SELECT unlock_at, freeze_at FROM quizzes WHERE id=$1', [quizId]);
      if (quiz.rows.length > 0) {
        const freezeDate = new Date(quiz.rows[0].freeze_at);
        const windowStart = new Date(freezeDate.getTime() - 48 * 60 * 60 * 1000);
        
        // Note: We can't check expired sessions, but we can check current ones
        console.log(`\nNote: Sessions expire after 30 days. Quiz ${quizId} freeze date: ${freezeDate}`);
        console.log(`      If submissions were more than 30 days ago, sessions won't be available.`);
      }
    } catch (e) {
      if (e.message.includes('does not exist') || e.message.includes('relation "session"')) {
        console.log('  Session table does not exist or is not accessible.');
      } else {
        console.log(`  Error checking session table: ${e.message}`);
      }
    }
    
    // 2. Instructions for checking server logs
    console.log('\n2. Server Log Sources:');
    console.log('   The application logs submissions with this format:');
    console.log(`   [submit] Quiz ${quizId}, User <email>: Graded X questions, total points: Y`);
    console.log(`   [gradeQuiz] Quiz ${quizId}, User <email>: X questions graded, total points: Y`);
    console.log('\n   Check these locations for server logs:');
    console.log('   - Railway: Railway dashboard > Deployments > View Logs');
    console.log('   - Heroku: heroku logs --tail --app <app-name>');
    console.log('   - Docker: docker logs <container-name>');
    console.log('   - PM2: pm2 logs');
    console.log('   - Systemd: journalctl -u <service-name>');
    console.log('   - Local: Check terminal/console where server was running');
    console.log('\n   Search for:');
    console.log(`   - "[submit] Quiz ${quizId}"`);
    console.log(`   - "[gradeQuiz] Quiz ${quizId}"`);
    console.log(`   - "POST /quiz/${quizId}/submit"`);
    
    // 3. PostgreSQL query logs
    console.log('\n3. PostgreSQL Query Logs:');
    console.log('   If PostgreSQL query logging is enabled, check for:');
    console.log(`   - INSERT INTO responses ... WHERE quiz_id = ${quizId}`);
    console.log(`   - DELETE FROM questions WHERE quiz_id = ${quizId}`);
    console.log('   - CASCADE DELETE operations');
    console.log('\n   To enable query logging (if not already enabled):');
    console.log('   - Set log_statement = "all" in postgresql.conf');
    console.log('   - Or set log_min_duration_statement = 0');
    console.log('   - Logs are typically in PostgreSQL data directory');
    
    // 4. Web server access logs
    console.log('\n4. Web Server Access Logs:');
    console.log('   If using a reverse proxy (nginx, Apache, etc.), check access logs for:');
    console.log(`   - POST requests to /quiz/${quizId}/submit`);
    console.log('   - These logs typically include IP addresses and timestamps');
    console.log('   - Location depends on your server setup');
    
    // 5. Check if there's a way to query historical data
    console.log('\n5. Other Database Sources:');
    console.log('   Checking for any audit tables or historical data...');
    
    // Check if there are any other tables that might have submission data
    const tables = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
        AND table_type = 'BASE TABLE'
        AND table_name NOT IN ('responses', 'questions', 'quizzes', 'players', 'session')
      ORDER BY table_name
    `);
    
    console.log(`   Found ${tables.rows.length} other tables:`);
    tables.rows.forEach(t => {
      console.log(`     - ${t.table_name}`);
    });
    
    // Check if responses table has any triggers or audit mechanisms
    const triggers = await pool.query(`
      SELECT trigger_name, event_manipulation, event_object_table
      FROM information_schema.triggers
      WHERE event_object_table = 'responses'
    `);
    
    if (triggers.rows.length > 0) {
      console.log('\n   Found triggers on responses table:');
      triggers.rows.forEach(t => {
        console.log(`     - ${t.trigger_name} (${t.event_manipulation})`);
      });
    } else {
      console.log('\n   No triggers found on responses table (no audit trail)');
    }
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await pool.end();
  }
}

const quizId = process.argv[2] || 4;
checkAdditionalSources(Number(quizId));

