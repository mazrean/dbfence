# Every phase runs on a shared server, so everything whose name does not
# start with e2e_ is ignored: --prune never drops it. RE2 has no lookahead,
# so the pattern spells out "not e2e_": a mismatch in one of the first four
# characters, or a name shorter than four. Role patterns also match
# name@host, which starts with the name.

ignore {
  roles     = ["[^e].*|e[^2].*|e2[^e].*|e2e[^_].*|.{0,3}"]
  databases = ["[^e].*|e[^2].*|e2[^e].*|e2e[^_].*|.{0,3}"]
}
