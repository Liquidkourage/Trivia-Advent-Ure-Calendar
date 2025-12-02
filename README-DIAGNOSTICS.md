# Diagnostic Scripts for Finding Deleted Submissions

These scripts help identify who submitted to a quiz before responses were deleted.

## Prerequisites

1. **Node.js installed** - Check with: `node --version`
2. **Database connection** - Make sure your `.env` file has `DATABASE_URL` set
3. **Dependencies installed** - Run `npm install` if you haven't already

## How to Run

### Option 1: Find Likely Submitters (Activity Pattern Analysis)

This analyzes player activity patterns to identify who likely submitted:

```bash
node find-deleted-submissions.js 4
```

Replace `4` with the quiz ID you want to check.

**What it does:**
- Finds players who submitted nearby quizzes (within 7 days)
- Identifies players who submitted nearby quizzes but NOT the target quiz
- These are likely candidates whose submissions were deleted

### Option 2: Check Additional Sources (Sessions, Logs, etc.)

This checks session tables and provides instructions for checking server logs:

```bash
node check-additional-sources.js 4
```

Replace `4` with the quiz ID you want to check.

**What it does:**
- Checks PostgreSQL session table for active sessions
- Provides instructions for checking server console logs
- Lists other potential sources (PostgreSQL logs, web server logs, etc.)

## Step-by-Step Instructions

1. **Open a terminal/command prompt**
   - Windows: PowerShell or Command Prompt
   - Mac/Linux: Terminal

2. **Navigate to the project directory**
   ```bash
   cd "C:\Users\liqui\World Trivia Federation\advent"
   ```
   (Or wherever your project is located)

3. **Make sure you're in the right directory**
   ```bash
   # Check that you can see the scripts
   dir find-deleted-submissions.js
   # Or on Mac/Linux:
   ls find-deleted-submissions.js
   ```

4. **Run the script**
   ```bash
   node find-deleted-submissions.js 4
   ```

5. **View the output**
   - The script will print analysis results to the console
   - Look for the "LIKELY SUBMITTERS" section

## Example Output

```
=== Searching for traces of deleted submissions for Quiz 4 ===

Quiz: Quiz Title
Unlocked: 2024-12-04T12:00:00Z
Freeze at: 2024-12-05T12:00:00Z

2. Checking for players who submitted OTHER quizzes around the same time...
Found 15 players who were active during that time window:
  - player1@example.com (submitted 3 other quiz(zes) during that window)
  - player2@example.com (submitted 2 other quiz(zes) during that window)
  ...

⚠️ LIKELY SUBMITTERS (submitted nearby quizzes but NOT quiz 4):
  - player1@example.com (submitted 3 nearby quiz(zes))
  - player2@example.com (submitted 2 nearby quiz(zes))
```

## Troubleshooting

### "Cannot find module 'pg'"
Run: `npm install`

### "DATABASE_URL is not defined"
Make sure your `.env` file exists and contains:
```
DATABASE_URL=postgresql://user:password@host:port/database
```

### "SyntaxError: Cannot use import statement"
Make sure you're using Node.js 14+ and the scripts are using ES modules (they should be - this is already fixed).

### Script runs but shows no results
- Check that the quiz ID is correct
- Verify the quiz exists in the database
- Check that there are actually players who submitted nearby quizzes

## Alternative: Use Web Interface

Instead of command-line scripts, you can use the web interface:

1. Go to: `/admin/quiz/4/find-deleted-submissions`
2. Replace `4` with your quiz ID
3. View the same analysis in your browser

## Most Reliable Source: Server Logs

**The most reliable way** to find deleted submissions is to check your server console logs. Every submission is logged with the user's email:

```
[submit] Quiz 4, User player@example.com: Graded 10 questions, total points: 45
```

See `check-additional-sources.js` output for instructions on where to find logs based on your hosting platform.

