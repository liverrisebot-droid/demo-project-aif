/*
INTENTIONAL SYNTAX-ANALYSIS TEST FIXTURE.
This file is deliberately invalid and is not loaded by the application.

Correct example:
function parseTask(task) {
    return task.id;
}
*/

// ISSUE: missing closing parenthesis/bracket.
function parseTask(task {

// ISSUE: malformed object literal.
const metadata = { status: "pending", priority: 1;

// ISSUE: unterminated string.
const message = "Task created;
