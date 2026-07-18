# Hammer — TryHackMe Writeup

Writeup for the [Hammer](https://tryhackme.com/room/hammer) room on TryHackMe.
Two flags: an authentication bypass via a brute-forceable password-reset flow, and a privilege-escalation-to-RCE chain via JWT `kid` header injection.

## Recon

Nmap shows two open ports: `22` (SSH) and `1337` (HTTP), which hosts a login page.

An initial directory scan with a standard wordlist doesn't turn up much of interest.

![gobuster initial scan](screenshots/01-gobuster-initial-dir-enum.png)

Checking the login page's source reveals a developer comment: all app directories must be prefixed `hmr_`.

![hmr_ naming hint in source](screenshots/02-login-source-hmr-naming-hint.png)

Re-running `ffuf` with that prefix uncovers a `hmr_logs` directory.

![ffuf hmr_ fuzzing](screenshots/03-ffuf-hmr-prefix-fuzzing.png)

`hmr_logs/error.logs` leaks a valid application email address, `tester@hammer.thm`.

![error.logs](screenshots/04-hmr-logs-error-log.png)

## Flag 1 — Authentication bypass (`THM{AuthBypass3D}`)

Using the leaked email on the "forgot password" flow triggers a 4-digit recovery code, valid only for a short time window — small enough of a search space to brute-force before it expires.

![recovery code page](screenshots/05-reset-password-recovery-code-page.png)

Automating with `ffuf` against all 10,000 combinations, spoofing `X-Forwarded-For` per request to dodge rate-limiting:

\`\`\`bash
seq 0000 9999 > numbers.txt
ffuf -w numbers.txt -u "http://<TARGET_IP>:1337/reset_password.php" \
  -X POST -d "recovery_code=FUZZ&s=60" \
  -H "Cookie: PHPSESSID=<session>" \
  -H "X-Forwarded-For: FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "Invalid" -s
\`\`\`

![ffuf brute force](screenshots/06-ffuf-recovery-code-bruteforce-terminal.png)

The correct code resets the password:

![reset password form](screenshots/07-reset-password-form.png)

Logging in with the new credentials:

![login](screenshots/8-login-with-new-password.png)

**Flag 1:** `THM{AuthBypass3D}`

![dashboard flag 1](screenshots/9-flag1-dashboard-authbypass.png)

## Flag 2 — JWT `kid` injection → RCE (`THM{RUNANYCOMMAND1337}`)

The dashboard exposes a command runner (`execute_command.php`), authorized via a JWT bearer token. Decoding the token shows a `kid` (Key ID) header pointing to a local key file path, and a `role: user` claim.

![captured JWT](screenshots/10-jwt-token-captured-terminal.png)

Since the app trusts the `kid` path to locate the signing key, fetching that file directly discloses the actual signing secret:

\`\`\`bash
curl -s http://<TARGET_IP>:1337/188ade1.key
\`\`\`

![fetching signing key](screenshots/11-curl-fetch-signing-key.png)

With the real secret in hand, a new JWT can be forged with `role: admin`, signed correctly:

![forged JWT](screenshots/12-jwt-forge-kid-role-admin.png)

The signature verifies:

![signature verified](screenshots/13-jwt-forge-signature-verified.png)

Swapping the forged token into the `Authorization` header (and cookie) and hitting `execute_command.php` returns the second flag:

**Flag 2:** `THM{RUNANYCOMMAND1337}`

![RCE flag via Burp](screenshots/14-burp-repeater-execute-command-flag2.png)

## Takeaways

- Recovery codes need proper rate-limiting that can't be bypassed with a spoofable header like `X-Forwarded-For`, and a 4-digit numeric OTP (only 10,000 possibilities) is far too small a search space regardless — it should be longer and alphanumeric to resist brute-forcing even without rate-limit bypass.
- Never derive a JWT signing key path from an attacker-controlled `kid` header — validate it against an allowlist, or better, don't store the key on a web-accessible path at all.
