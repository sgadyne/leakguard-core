# Fixed-argv check

`firm_check.py` implements the LeakGuard script-check v1 JSON protocol. The
example detects only the synthetic string `FIRM-SCRIPT-REVIEW-MARKER`. It
accepts one bounded JSON request on stdin and returns only the fixed rule ID,
line number and review severity. It never returns source text or exception
details.

Use an absolute interpreter and script path in `argv`. The command is fixed;
do not interpolate source text into arguments or a shell command. See the root
firm setup guide for a registry example and the per-user runtime setup.
