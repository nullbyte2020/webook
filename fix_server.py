import re

filepath = r'D:/webook/kimiko/webapp3/server.js'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')

# Find the line with "emitStatus('seats-failed'" - this is where our new function ends
# Then find the first broken "async function runSession" after that
seats_failed_line = None
for i, line in enumerate(lines):
    if "emitStatus('seats-failed'" in line:
        seats_failed_line = i
        break

print(f"Found 'seats-failed' at line {seats_failed_line + 1}")

# Find the first broken runSession after seats-failed
first_broken_runsession = None
for i in range(seats_failed_line, len(lines)):
    if 'async function runSession' in lines[i]:
        first_broken_runsession = i
        break

print(f"First broken runSession at line {first_broken_runsession + 1}")

# Find the real runSession (the one with targetSeatCount)
real_runsession = None
for i in range(first_broken_runsession, len(lines)):
    if 'async function runSession' in lines[i] and 'targetSeatCount' in lines[i+2]:
        real_runsession = i
        break

print(f"Real runSession at line {real_runsession + 1}")

# Remove lines from first_broken_runsession to real_runsession (exclusive)
# Keep the real runSession
new_lines = lines[:first_broken_runsession] + lines[real_runsession:]

new_content = '\n'.join(new_lines)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"Removed broken code from lines {first_broken_runsession + 1} to {real_runsession}")
print(f"File saved. New line count: {len(new_lines)}")
