# Leaderboard Performance Analysis

## Executive Summary

The leaderboard pages have several performance bottlenecks that can cause slow load times, especially as the number of players and responses grows. The main issues are:

1. **N+1 Query Problem** - Overall leaderboard executes one query per player for stats
2. **Missing Database Indexes** - Critical indexes for `submitted_at` filtering are absent
3. **Expensive Regex Operations** - Normalization happens in SQL with regex on every row
4. **No Caching** - Leaderboards are recalculated on every page load
5. **Redundant Author Bonus Calculations** - Author averages recalculated multiple times
6. **Inefficient Stats Calculation** - Complex CTEs with EXISTS subqueries run for every player

## Current Implementation Analysis

### 1. Per-Quiz Leaderboard (`/quiz/:id/leaderboard`)

**Location:** Lines 7919-8177

#### Queries Executed:
1. **Quiz Info Query** (Line 7923)
   ```sql
   SELECT id, title, freeze_at, author_email FROM quizzes WHERE id = $1
   ```
   - **Performance:** ✅ Fast (indexed primary key)
   - **Impact:** Minimal

2. **Main Leaderboard Query** (Lines 7926-7933)
   ```sql
   SELECT r.user_email, COALESCE(p.username, r.user_email) AS handle, 
          SUM(r.points) AS points, MIN(r.submitted_at) AS first_time
   FROM responses r
   LEFT JOIN players p ON p.email = r.user_email
   WHERE r.quiz_id = $1 AND r.submitted_at IS NOT NULL AND r.submitted_at <= $2
   GROUP BY r.user_email, handle
   ```
   - **Performance:** ⚠️ Moderate
   - **Issues:**
     - Uses `idx_responses_quiz_user` (good)
     - But filters on `submitted_at` which has NO index
     - LEFT JOIN on `players.email` (should be indexed, but not explicitly)
   - **Estimated Rows Scanned:** All responses for quiz × players (could be 1000s)

3. **Stats Query** (Lines 7937-7982)
   ```sql
   WITH normalized_responses AS (
     SELECT r.id, r.user_email, r.question_id, r.response_text, 
            r.override_correct, r.points, q.answer,
            LOWER(REGEXP_REPLACE(TRIM(r.response_text), '[^a-z0-9]', '', 'g')) as norm_response,
            LOWER(REGEXP_REPLACE(TRIM(q.answer), '[^a-z0-9]', '', 'g')) as norm_answer
     FROM responses r
     JOIN questions q ON q.id = r.question_id
     WHERE r.quiz_id = $1 AND r.submitted_at IS NOT NULL AND r.submitted_at <= $2
   ),
   accepted_norms AS (
     SELECT DISTINCT r2.question_id,
            LOWER(REGEXP_REPLACE(TRIM(r2.response_text), '[^a-z0-9]', '', 'g')) as accepted_norm
     FROM responses r2
     WHERE r2.quiz_id = $1
       AND r2.override_correct = true 
       AND r2.response_text IS NOT NULL 
       AND TRIM(r2.response_text) != ''
   )
   SELECT nr.user_email,
     SUM(CASE WHEN ... END) as correct_count,
     SUM(nr.points) as total_points
   FROM normalized_responses nr
   GROUP BY nr.user_email
   ```
   - **Performance:** 🔴 **SLOW**
   - **Issues:**
     - **Regex operations on EVERY row** - `REGEXP_REPLACE` is expensive
     - **Two CTEs** - Materializes intermediate results
     - **EXISTS subquery** in CASE statement (line 7971-7975) - Runs for every row
     - **No index on `submitted_at`** - Full table scan
   - **Estimated Cost:** O(n × m) where n = responses, m = accepted norms

4. **Author Bonus Query** (Line 8011)
   ```sql
   -- Calls computeAuthorAveragePoints() which executes:
   SELECT user_email, SUM(points) AS total_points 
   FROM responses 
   WHERE quiz_id=$1 AND submitted_at IS NOT NULL 
   GROUP BY user_email
   ```
   - **Performance:** ⚠️ Moderate (duplicates work from main query)
   - **Issues:** Recalculates data already fetched

5. **Player Username Lookup** (Line 8013)
   ```sql
   SELECT username FROM players WHERE email=$1
   ```
   - **Performance:** ✅ Fast (if email is indexed)
   - **Impact:** Minimal

**Total Queries:** 4-5 queries per page load
**Estimated Load Time:** 500ms - 2s (depending on quiz size)

---

### 2. Overall Leaderboard (`/leaderboard`)

**Location:** Lines 8696-8999

#### Queries Executed:

1. **Main Aggregation Query** (Lines 8699-8705)
   ```sql
   SELECT r.user_email, COALESCE(p.username, r.user_email) AS handle, SUM(r.points) AS points
   FROM responses r
   LEFT JOIN players p ON p.email = r.user_email
   WHERE r.submitted_at IS NOT NULL
   GROUP BY r.user_email, handle
   ```
   - **Performance:** 🔴 **VERY SLOW**
   - **Issues:**
     - **Scans ALL responses** across ALL quizzes
     - **No WHERE clause filtering** - processes entire `responses` table
     - **No index on `submitted_at`** - cannot use index for filtering
     - **GROUP BY** on large dataset
   - **Estimated Rows Scanned:** Potentially 100,000+ rows

2. **Author Bonus Loop** (Lines 8716-8738)
   ```sql
   -- For EACH quiz author:
   SELECT id, author_email FROM quizzes WHERE author_email IS NOT NULL
   -- Then for EACH author:
   SELECT COUNT(*) FROM responses WHERE user_email = $1
   -- Then computeAuthorAveragePoints() for EACH quiz
   ```
   - **Performance:** 🔴 **N+1 Problem**
   - **Issues:**
     - Loops through all quiz authors (could be 60+)
     - Executes 2-3 queries per author
     - **Total: 120-180+ queries** if 60 quizzes
   - **Estimated Queries:** 60-180 queries

3. **Stats Calculation Loop** (Lines 8743-8801)
   ```sql
   -- For EACH player in leaderboard:
   WITH normalized_responses AS (
     SELECT ... LOWER(REGEXP_REPLACE(...)) ...
     FROM responses r
     JOIN questions q ON q.id = r.question_id
     WHERE r.user_email = $1 AND r.submitted_at IS NOT NULL
   ),
   accepted_norms AS (...)
   SELECT COUNT(DISTINCT nr.quiz_id) as quizzes_submitted,
          SUM(CASE WHEN ... END) as correct_count,
          SUM(nr.points) as total_points
   FROM normalized_responses nr
   ```
   - **Performance:** 🔴 **CRITICAL N+1 Problem**
   - **Issues:**
     - **One query per player** in leaderboard
     - If 500 players → **500 queries**
     - Each query does regex normalization on ALL their responses
     - Complex CTEs with EXISTS subqueries
   - **Estimated Queries:** 100-500+ queries (one per player)

4. **Quiz Links Query** (Lines 8855-8864)
   ```sql
   SELECT q.id, q.title, q.unlock_at, q.quiz_type,
          COUNT(DISTINCT r.user_email) as participant_count,
          MAX(r.submitted_at) as last_submission
   FROM quizzes q
   LEFT JOIN responses r ON r.quiz_id = q.id AND r.submitted_at IS NOT NULL
   GROUP BY q.id, q.title, q.unlock_at, q.quiz_type
   HAVING COUNT(DISTINCT r.user_email) > 0
   ORDER BY q.unlock_at DESC
   ```
   - **Performance:** ⚠️ Moderate
   - **Issues:** Scans all quizzes and responses

**Total Queries:** **100-700+ queries** per page load
**Estimated Load Time:** **5-30+ seconds** (depending on player count)

---

### 3. Quizmas Leaderboard (`/quizmas/leaderboard`)

**Location:** Lines 8412-8623

#### Queries Executed:

Similar structure to overall leaderboard but:
- Filters by date range (Dec 26 - Jan 6)
- Still has N+1 problem for stats (lines 8473-8520)
- Still loops through authors (lines 8439-8470)

**Total Queries:** **50-300+ queries** per page load
**Estimated Load Time:** **3-15+ seconds**

---

## Database Index Analysis

### Current Indexes:
```sql
CREATE INDEX idx_responses_quiz_user ON responses(quiz_id, user_email);
CREATE INDEX idx_questions_quiz_id ON questions(quiz_id);
CREATE INDEX idx_quizzes_unlock_at ON quizzes(unlock_at);
CREATE INDEX idx_quizzes_freeze_at ON quizzes(freeze_at);
```

### Missing Critical Indexes:

1. **`responses.submitted_at`** - Used in EVERY leaderboard query
   ```sql
   CREATE INDEX idx_responses_submitted_at ON responses(submitted_at);
   ```

2. **Composite index for quiz leaderboards:**
   ```sql
   CREATE INDEX idx_responses_quiz_submitted ON responses(quiz_id, submitted_at);
   ```

3. **Composite index for user queries:**
   ```sql
   CREATE INDEX idx_responses_user_submitted ON responses(user_email, submitted_at);
   ```

4. **Index for author bonus queries:**
   ```sql
   CREATE INDEX idx_responses_user_quiz ON responses(user_email, quiz_id, submitted_at);
   ```

5. **Players email index (if not exists):**
   ```sql
   CREATE INDEX idx_players_email ON players(email);
   ```

---

## Performance Bottlenecks Ranked

### 🔴 Critical (Immediate Impact)

1. **N+1 Query Problem in Overall Leaderboard**
   - **Impact:** 100-500+ queries per page load
   - **Fix Priority:** HIGHEST
   - **Solution:** Batch stats calculation into single query

2. **Missing `submitted_at` Index**
   - **Impact:** Full table scans on every query
   - **Fix Priority:** HIGHEST
   - **Solution:** Add indexes listed above

3. **Regex Operations in SQL**
   - **Impact:** CPU-intensive operations on every row
   - **Fix Priority:** HIGH
   - **Solution:** Pre-compute normalized values or move to application layer

### ⚠️ High Priority

4. **Author Bonus N+1 Problem**
   - **Impact:** 60-180 queries for author bonuses
   - **Fix Priority:** HIGH
   - **Solution:** Batch author bonus calculation

5. **No Caching**
   - **Impact:** Recalculates everything on every page load
   - **Fix Priority:** HIGH
   - **Solution:** Implement Redis/memory caching with TTL

6. **Overall Leaderboard Scans All Data**
   - **Impact:** Processes entire responses table
   - **Fix Priority:** MEDIUM-HIGH
   - **Solution:** Add date range filtering or materialized view

### 💡 Medium Priority

7. **Redundant Author Average Calculations**
   - **Impact:** Duplicate work
   - **Fix Priority:** MEDIUM
   - **Solution:** Cache author averages per quiz

8. **Complex CTEs with EXISTS Subqueries**
   - **Impact:** Query planner struggles to optimize
   - **Fix Priority:** MEDIUM
   - **Solution:** Refactor to JOINs or pre-computed tables

---

## Recommended Solutions

### Phase 1: Quick Wins (Immediate Impact)

1. **Add Database Indexes** ⏱️ 5 minutes
   ```sql
   CREATE INDEX CONCURRENTLY idx_responses_submitted_at ON responses(submitted_at);
   CREATE INDEX CONCURRENTLY idx_responses_quiz_submitted ON responses(quiz_id, submitted_at);
   CREATE INDEX CONCURRENTLY idx_responses_user_submitted ON responses(user_email, submitted_at);
   CREATE INDEX CONCURRENTLY idx_players_email ON players(email);
   ```
   **Expected Improvement:** 50-80% faster queries

2. **Batch Stats Calculation** ⏱️ 2-4 hours
   - Replace N+1 loop with single aggregated query
   - Use window functions or GROUP BY with CASE statements
   **Expected Improvement:** 90%+ reduction in queries

3. **Batch Author Bonus Calculation** ⏱️ 1-2 hours
   - Calculate all author bonuses in one query
   - Use JOINs instead of loops
   **Expected Improvement:** 95%+ reduction in queries

### Phase 2: Optimization (High Impact)

4. **Implement Caching** ⏱️ 4-8 hours
   - Cache leaderboard results with 5-15 minute TTL
   - Invalidate on new submissions or grading changes
   - Use Redis or in-memory cache
   **Expected Improvement:** 99% faster for cached requests

5. **Pre-compute Normalized Values** ⏱️ 4-6 hours
   - Add `normalized_response` column to responses table
   - Update on insert/update via trigger or application logic
   - Remove regex from queries
   **Expected Improvement:** 30-50% faster stats queries

6. **Materialized View for Overall Leaderboard** ⏱️ 2-4 hours
   - Create materialized view with aggregated scores
   - Refresh periodically (every 5-15 minutes)
   - Use INSTEAD OF triggers for real-time updates
   **Expected Improvement:** 95%+ faster overall leaderboard

### Phase 3: Advanced Optimization (Long-term)

7. **Denormalized Stats Table** ⏱️ 8-12 hours
   - Create `player_quiz_stats` table
   - Update on response submission/grading
   - Pre-compute correct_count, points, etc.
   **Expected Improvement:** Near-instant leaderboard queries

8. **Read Replicas** ⏱️ Infrastructure setup
   - Route leaderboard queries to read replica
   - Reduces load on primary database
   **Expected Improvement:** Better scalability

---

## Estimated Performance Improvements

### Current State:
- **Per-Quiz Leaderboard:** 500ms - 2s
- **Overall Leaderboard:** 5-30+ seconds
- **Quizmas Leaderboard:** 3-15+ seconds

### After Phase 1 (Indexes + Batching):
- **Per-Quiz Leaderboard:** 100-500ms (50-80% improvement)
- **Overall Leaderboard:** 1-3 seconds (80-90% improvement)
- **Quizmas Leaderboard:** 500ms-2s (70-85% improvement)

### After Phase 2 (Caching + Pre-computation):
- **Per-Quiz Leaderboard:** 10-50ms (95%+ improvement)
- **Overall Leaderboard:** 50-200ms (95%+ improvement)
- **Quizmas Leaderboard:** 20-100ms (95%+ improvement)

### After Phase 3 (Denormalization):
- **All Leaderboards:** <50ms (near-instant)

---

## Implementation Notes

### Index Creation:
- Use `CREATE INDEX CONCURRENTLY` to avoid locking tables
- Monitor index size (may add 10-20% to database size)
- Consider partial indexes for filtered queries

### Caching Strategy:
- Cache key format: `leaderboard:quiz:{id}` or `leaderboard:overall`
- TTL: 5-15 minutes (balance freshness vs performance)
- Invalidation: On response submission, grading changes, quiz updates
- Consider cache warming for popular leaderboards

### Query Refactoring:
- Test query plans with `EXPLAIN ANALYZE`
- Monitor query execution times
- Consider query timeouts for safety

### Monitoring:
- Add query timing logs
- Monitor cache hit rates
- Track database load
- Set up alerts for slow queries (>1s)

---

## Risk Assessment

### Low Risk:
- Adding indexes (can be done with CONCURRENTLY)
- Implementing caching (can be disabled if issues)

### Medium Risk:
- Query refactoring (needs thorough testing)
- Pre-computing normalized values (data consistency concerns)

### High Risk:
- Materialized views (refresh timing critical)
- Denormalized tables (data sync complexity)

---

## Next Steps

1. **Approve this analysis**
2. **Prioritize fixes** (recommend Phase 1 first)
3. **Create implementation plan** for approved fixes
4. **Test in staging** before production
5. **Monitor performance** after deployment

