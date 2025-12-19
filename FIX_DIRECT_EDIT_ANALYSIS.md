# Fixing Direct Quiz Edit - Database Analysis

## Problem Summary

An author emailed their questions instead of using the submission link, and an admin directly edited the quiz instead of publishing it through the proper writer submission flow. This left the database in an inconsistent state.

## What Happens in Proper Flow

When a writer submission is published via `/admin/writer-submissions/:id/publish`:

1. **Creates/Updates Quiz** in `quizzes` table
2. **Updates `writer_invites` table**:
   ```sql
   UPDATE writer_invites 
   SET published_at = NOW(), active = FALSE 
   WHERE token = [submission_token]
   ```
3. **Links quiz to invite** via `author_email` matching `writer_invites.email`

## What's Broken Now

The quiz exists in `quizzes` table, but:
- ❌ `writer_invites.published_at` is still `NULL`
- ❌ `writer_invites.active` is still `TRUE` (probably)
- ❌ No `writer_submissions` record exists (since they emailed instead)

## Impact on Calendar View

The admin calendar (`/admin/calendar`) checks:
- **Line 3736-3742**: Looks for `writer_invites.published_at IS NOT NULL` to mark slots as "published"
- **Line 3727-3734**: Shows unpublished submissions where `published_at IS NULL`
- **Line 3849**: Checks if slot is "missing submission" (`!hasPublishedSubmission && !hasUnpublished`)

**Result**: Calendar will show:
- Either "⚠️ Unpublished Submission" warning
- Or "Missing submission" indicator
- Even though the quiz is actually published and live

## Database Fix Required

### Step 1: Identify the Quiz and Author

Find the quiz that was directly edited:
```sql
-- Replace [QUIZ_ID] with the actual quiz ID
SELECT 
  id, 
  title, 
  unlock_at, 
  author, 
  author_email,
  quiz_type
FROM quizzes 
WHERE id = [QUIZ_ID];
```

### Step 2: Find Matching Writer Invite

Match the quiz to a `writer_invites` record using multiple strategies:

```sql
-- Strategy 1: Match by author_email
SELECT 
  wi.token,
  wi.author,
  wi.email,
  wi.slot_date,
  wi.slot_half,
  wi.published_at,
  wi.active,
  wi.submitted_at
FROM writer_invites wi
WHERE wi.email = '[QUIZ_AUTHOR_EMAIL]'  -- from quiz.author_email
  AND wi.published_at IS NULL;

-- Strategy 2: Match by author name AND slot
SELECT 
  wi.token,
  wi.author,
  wi.email,
  wi.slot_date,
  wi.slot_half,
  wi.published_at,
  wi.active
FROM writer_invites wi
WHERE LOWER(TRIM(wi.author)) = LOWER(TRIM('[QUIZ_AUTHOR_NAME]'))  -- from quiz.author
  AND wi.slot_date = '[YYYY-MM-DD]'  -- Extract from quiz.unlock_at
  AND wi.slot_half = '[AM|PM]'  -- Extract from quiz.unlock_at (0 = AM, 12 = PM)
  AND wi.published_at IS NULL;

-- Strategy 3: Match by slot only (if author name/email don't match)
SELECT 
  wi.token,
  wi.author,
  wi.email,
  wi.slot_date,
  wi.slot_half,
  wi.published_at,
  wi.active
FROM writer_invites wi
WHERE wi.slot_date = '[YYYY-MM-DD]'  -- Extract from quiz.unlock_at
  AND wi.slot_half = '[AM|PM]'  -- Extract from quiz.unlock_at
  AND wi.published_at IS NULL
ORDER BY wi.created_at DESC;
```

### Step 3: Extract Slot Info from Quiz

Convert `unlock_at` to slot date/half:
```sql
-- For a quiz with unlock_at, extract slot info:
SELECT 
  id,
  title,
  unlock_at,
  author,
  author_email,
  -- Extract date (YYYY-MM-DD)
  TO_CHAR(unlock_at AT TIME ZONE 'America/New_York', 'YYYY-MM-DD') as slot_date,
  -- Extract half (AM if hour = 0, PM if hour = 12)
  CASE 
    WHEN EXTRACT(HOUR FROM unlock_at AT TIME ZONE 'America/New_York') = 0 THEN 'AM'
    WHEN EXTRACT(HOUR FROM unlock_at AT TIME ZONE 'America/New_York') = 12 THEN 'PM'
    ELSE NULL
  END as slot_half
FROM quizzes
WHERE id = [QUIZ_ID];
```

### Step 4: Update Writer Invite

Once you've identified the correct `writer_invites` record:

```sql
-- Mark as published and deactivate
UPDATE writer_invites 
SET 
  published_at = NOW(),
  active = FALSE
WHERE token = '[FOUND_TOKEN]';

-- Verify the update
SELECT 
  token,
  author,
  email,
  slot_date,
  slot_half,
  published_at,
  active
FROM writer_invites
WHERE token = '[FOUND_TOKEN]';
```

### Step 5: Optional - Create Writer Submission Record

If you want to create a `writer_submissions` record for completeness (not strictly necessary):

```sql
-- First, get the token from writer_invites
SELECT token FROM writer_invites WHERE token = '[FOUND_TOKEN]';

-- Then create a submission record (if it doesn't exist)
INSERT INTO writer_submissions (token, author, data, submitted_at)
VALUES (
  '[FOUND_TOKEN]',
  '[AUTHOR_NAME]',  -- from quiz.author
  '{"questions":[]}'::jsonb,  -- Empty since questions are already in quiz
  NOW()
)
ON CONFLICT DO NOTHING;
```

## Complete Fix Query (All-in-One)

Here's a comprehensive query that does most of the work:

```sql
-- Step 1: Find quiz details
WITH quiz_info AS (
  SELECT 
    id as quiz_id,
    title,
    unlock_at,
    author,
    author_email,
    TO_CHAR(unlock_at AT TIME ZONE 'America/New_York', 'YYYY-MM-DD') as slot_date,
    CASE 
      WHEN EXTRACT(HOUR FROM unlock_at AT TIME ZONE 'America/New_York') = 0 THEN 'AM'
      WHEN EXTRACT(HOUR FROM unlock_at AT TIME ZONE 'America/New_York') = 12 THEN 'PM'
      ELSE NULL
    END as slot_half
  FROM quizzes
  WHERE id = [QUIZ_ID]
),
-- Step 2: Find matching writer invite
matching_invite AS (
  SELECT 
    wi.token,
    wi.author,
    wi.email,
    wi.slot_date,
    wi.slot_half,
    wi.published_at,
    wi.active,
    -- Priority: email match > name+slot match > slot only
    CASE 
      WHEN qi.author_email IS NOT NULL AND LOWER(wi.email) = LOWER(qi.author_email) THEN 1
      WHEN LOWER(TRIM(wi.author)) = LOWER(TRIM(qi.author)) 
        AND wi.slot_date = qi.slot_date 
        AND wi.slot_half = qi.slot_half THEN 2
      WHEN wi.slot_date = qi.slot_date AND wi.slot_half = qi.slot_half THEN 3
      ELSE 99
    END as match_priority
  FROM writer_invites wi
  CROSS JOIN quiz_info qi
  WHERE wi.published_at IS NULL
    AND (
      (qi.author_email IS NOT NULL AND LOWER(wi.email) = LOWER(qi.author_email))
      OR (LOWER(TRIM(wi.author)) = LOWER(TRIM(qi.author)) 
          AND wi.slot_date = qi.slot_date 
          AND wi.slot_half = qi.slot_half)
      OR (wi.slot_date = qi.slot_date AND wi.slot_half = qi.slot_half)
    )
  ORDER BY match_priority ASC, wi.created_at DESC
  LIMIT 1
)
-- Step 3: Show what will be updated
SELECT 
  qi.*,
  mi.token as invite_token,
  mi.author as invite_author,
  mi.email as invite_email,
  mi.published_at as current_published_at,
  mi.active as current_active,
  'UPDATE writer_invites SET published_at = NOW(), active = FALSE WHERE token = ''' || mi.token || ''';' as update_query
FROM quiz_info qi
LEFT JOIN matching_invite mi ON true;
```

## Verification Queries

After updating, verify the fix:

```sql
-- Check calendar view data
SELECT 
  q.id as quiz_id,
  q.title,
  q.unlock_at,
  q.author,
  q.author_email,
  wi.token,
  wi.author as invite_author,
  wi.published_at,
  wi.active,
  CASE 
    WHEN wi.published_at IS NOT NULL THEN '✅ Published'
    ELSE '❌ Not Published'
  END as status
FROM quizzes q
LEFT JOIN writer_invites wi ON (
  (q.author_email IS NOT NULL AND LOWER(wi.email) = LOWER(q.author_email))
  OR (LOWER(TRIM(wi.author)) = LOWER(TRIM(q.author)))
)
WHERE q.id = [QUIZ_ID];
```

## Edge Cases

1. **Multiple writer invites for same author**: Use the one matching the quiz's `unlock_at` slot
2. **No matching writer invite**: The quiz might have been created manually without an invite
3. **Author email mismatch**: Match by author name + slot instead
4. **Slot mismatch**: If quiz was moved to different slot, match by author email/name only

## Prevention

To prevent this in the future:
- Always use `/admin/writer-submissions/:id/publish` to publish quizzes
- If questions come via email, create a `writer_submissions` record first, then publish
- Consider adding a database constraint or trigger to ensure consistency


