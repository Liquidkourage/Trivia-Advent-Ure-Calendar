// Emergency fix script to re-link responses to questions after question edit
// Run this if questions were deleted/recreated and responses are orphaned
// Usage: node fix-broken-quiz-responses.js <quiz_id>

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function fixQuiz(quizId) {
  try {
    console.log(`Fixing quiz ${quizId}...`);
    
    // Get all responses for this quiz
    const responses = await pool.query(
      `SELECT r.id, r.question_id, r.user_email, r.response_text, r.submitted_at
       FROM responses r
       WHERE r.quiz_id = $1 AND r.submitted_at IS NOT NULL`,
      [quizId]
    );
    
    console.log(`Found ${responses.rows.length} submitted responses`);
    
    // Get current questions
    const questions = await pool.query(
      'SELECT id, number FROM questions WHERE quiz_id = $1 ORDER BY number',
      [quizId]
    );
    
    console.log(`Found ${questions.rows.length} questions`);
    
    // Get old question numbers from responses (we need to match by some logic)
    // Since we can't know the old question numbers directly, we'll need to match by position
    // This is a best-effort fix - may not be perfect if questions were reordered
    
    // Strategy: Match responses to questions by trying to find the best match
    // For now, let's assume questions are in order and match by index
    // This is imperfect but better than nothing
    
    const questionByNumber = new Map();
    questions.rows.forEach(q => {
      questionByNumber.set(q.number, q.id);
    });
    
    // We need to figure out which old question_id maps to which new question number
    // Since we don't have that info, we'll need to match responses to questions
    // by finding responses that don't have a valid question_id
    
    const orphanedResponses = responses.rows.filter(r => {
      return !questions.rows.some(q => q.id === r.question_id);
    });
    
    console.log(`Found ${orphanedResponses.length} orphaned responses`);
    
    if (orphanedResponses.length === 0) {
      console.log('No orphaned responses found. Quiz may already be fixed.');
      return;
    }
    
    // For each orphaned response, we need to match it to a question
    // This is tricky - we can't know for sure which question it belongs to
    // Best we can do is match by user and try to infer from other responses
    
    // Get all responses grouped by user
    const byUser = new Map();
    responses.rows.forEach(r => {
      if (!byUser.has(r.user_email)) {
        byUser.set(r.user_email, []);
      }
      byUser.get(r.user_email).push(r);
    });
    
    // For each user, try to match orphaned responses to questions
    let fixed = 0;
    for (const [email, userResponses] of byUser) {
      const orphaned = userResponses.filter(r => orphanedResponses.some(or => or.id === r.id));
      const valid = userResponses.filter(r => !orphanedResponses.some(or => or.id === r.id));
      
      // If user has some valid responses, we can infer question numbers
      // Otherwise, we're stuck
      
      if (orphaned.length > 0 && valid.length > 0) {
        // Try to match orphaned responses to missing question numbers
        const validQuestionIds = new Set(valid.map(r => r.question_id));
        const usedQuestionNumbers = new Set();
        
        // Find which question numbers this user already has responses for
        valid.forEach(r => {
          const q = questions.rows.find(q => q.id === r.question_id);
          if (q) usedQuestionNumbers.add(q.number);
        });
        
        // Find available question numbers
        const availableNumbers = Array.from(questionByNumber.keys())
          .filter(n => !usedQuestionNumbers.has(n))
          .slice(0, orphaned.length);
        
        // Match orphaned responses to available question numbers
        for (let i = 0; i < Math.min(orphaned.length, availableNumbers.length); i++) {
          const response = orphaned[i];
          const questionNumber = availableNumbers[i];
          const newQuestionId = questionByNumber.get(questionNumber);
          
          await pool.query(
            'UPDATE responses SET question_id = $1 WHERE id = $2',
            [newQuestionId, response.id]
          );
          fixed++;
          console.log(`Fixed response ${response.id} -> question ${questionNumber} (id: ${newQuestionId})`);
        }
      }
    }
    
    console.log(`Fixed ${fixed} responses`);
    console.log('Done!');
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await pool.end();
  }
}

const quizId = process.argv[2];
if (!quizId) {
  console.error('Usage: node fix-broken-quiz-responses.js <quiz_id>');
  process.exit(1);
}

fixQuiz(Number(quizId));

