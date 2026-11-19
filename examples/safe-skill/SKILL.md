---
name: commit-message-helper
description: Use when the user asks for a git commit message. Summarizes staged changes into a conventional commit message.
allowed-tools: Bash(git diff:*), Bash(git status:*)
---

# Commit Message Helper

1. Run `git diff --staged` to read the staged changes.
2. Write a one-line summary under 72 characters in the conventional commits style.
3. Add a short body explaining *why* the change was made.
