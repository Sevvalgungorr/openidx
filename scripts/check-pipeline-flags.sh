#!/usr/bin/env bash
# Every flag the pipeline READS must be settable, and must arrive in the exact
# spelling the step compares against.
#
# This class of defect has now appeared three times in a row:
#   1. UPLOAD_SBOM was a baked-in literal "false", so the documented
#      pipeline variable could not override it.
#   2. It became a bare $(UPLOAD_SBOM) macro with no definition anywhere. An
#      undefined macro is NOT empty in Azure: it survives as the literal text
#      "$(UPLOAD_SBOM)", which is not "true", so the step printed
#      "SBOM upload disabled", exited 0 and uploaded nothing while looking
#      perfectly healthy. A run was found with UPLOAD_SBOM=true hardcoded
#      into the step body, which is what people do when a switch is broken.
#   3. A boolean parameter renders as "True", and the step compares to
#      "true", so without lower() it would have been silently off AGAIN.
#
# Each failure was invisible: the step was green every time. So this is a
# gate, not a comment.
set -uo pipefail
YML="${1:-deployments/ci/azure-pipelines-ziti.yml}"
[ -f "$YML" ] || { echo "PIPELINE_FLAGS=skipped (no $YML)"; exit 0; }

python3 - "$YML" <<'PYEOF'
import re, sys
path = sys.argv[1]
src = open(path, encoding="utf-8").read()

# Flags the step bodies actually read, with a shell default.
read = set(re.findall(r'\$\{([A-Z_][A-Z0-9_]*):-(?:true|false)\}', src))
# Flags an env: block supplies.
env = dict(re.findall(r'^\s+([A-Z_][A-Z0-9_]*):\s*"([^"]*)"\s*$', src, re.M))
# Declared parameters.
declared = set(re.findall(r'^\s+-\s+name:\s+([A-Z_][A-Z0-9_]*)\s*$', src, re.M))

bad = []
for flag in sorted(read):
    value = env.get(flag)
    if value is None:
        bad.append(f"{flag}: read by a step but never set in any env: block")
        continue
    if re.fullmatch(r'\$\([A-Z_]+\)', value):
        # A bare $(NAME) is a runtime MACRO, resolved from pipeline variables
        # and variable groups -- NOT from parameters. Declaring a parameter of
        # the same name does not define the macro, so accepting it here is
        # what let mutation M2 slip through on the first version of this gate.
        # Require the macro to be defined as a variable in this file.
        name = value[2:-1]
        defined_vars = set(re.findall(r'^\s+-\s+name:\s+([A-Z_][A-Z0-9_]*)\s*$',
                                      src.split('steps:')[0], re.M))
        param_names = set(re.findall(r'^\s+-\s+name:\s+([A-Z_][A-Z0-9_]*)\s*$',
                                     src.split('variables:')[0], re.M))
        if name not in (defined_vars - param_names):
            bad.append(f"{flag}: bare macro {value} is not defined as a "
                       f"variable; an undefined macro arrives as the literal "
                       f"text \"{value}\" and reads as OFF")
        continue
    m = re.fullmatch(r'\$\{\{\s*(lower\()?parameters\.([A-Z_]+)\)?\s*\}\}', value)
    if m:
        if m.group(2) not in declared:
            bad.append(f"{flag}: refers to parameters.{m.group(2)} which is not declared")
        elif not m.group(1):
            bad.append(f"{flag}: parameter used without lower(); a boolean "
                       f"renders as \"True\" and the step compares to \"true\", "
                       f"so it would be silently OFF")
        continue
    if value not in ("true", "false"):
        continue
    bad.append(f"{flag}: hardcoded literal \"{value}\"; the documented "
               f"variable cannot override it")

# A flag must never be forced on inside the step body: that bypasses the switch.
for flag in sorted(read):
    if re.search(r'^\s*%s=(true|false)\s*$' % flag, src, re.M):
        bad.append(f"{flag}: assigned literally inside a step body, which "
                   f"shadows the env: value and the parameter")

print("PIPELINE_FLAGS=%d" % len(bad))
for b in bad:
    print("  - " + b)
sys.exit(1 if bad else 0)
PYEOF
