# Redirect Hell: Multiverse of Madness - Solution

## Flag
```
L3m0nCTF{d1m3ns10n_h0pp1ng_w1th_th3_s0rc3r3r_supr3m3}
```

## Challenge Overview
- 16 dimensions with cinematic backgrounds
- Session-based obfuscated URLs (`/portal/<token>`)
- 1 second auto-redirects between dimensions
- Glass shatter transition effects
- 6 flag parts hidden in plain text across different locations

## Flag Part Locations

| Portal | Location | How to Find |
|--------|----------|-------------|
| 2 | HTML Comment | View Source → `<!-- FLAG_PART: L3m0nCTF{ -->` |
| 5 | HTTP Header | DevTools → Network → Headers → `X-Flag: d1m3ns10n_` |
| 8 | Cookie | DevTools → Application → Cookies → `flag_part: h0pp1ng_` |
| 11 | Hidden Input | View Source → `<input type="hidden" name="flag" value="w1th_th3_">` |
| 13 | JavaScript Variable | View Source → `var flagPart = "s0rc3r3r_";` |
| 14 | Page Title | `<title>supr3m3}</title>` |

## Automated Solve
```bash
python solve.py
```

## Manual Solve Steps
1. Start at http://localhost:5000
2. Open DevTools (F12)
3. Watch Network tab for headers/cookies
4. View page source at each portal for comments, hidden inputs, JS variables
5. Collect all 6 parts and concatenate
