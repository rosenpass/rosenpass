# Extensions to the proverif/cryptoverif language

BEGIN {
  buf=""
  module = ""
  err = 0
  long_alias_name = ""
  long_alias_value = ""
}

/^@module/ {
  module=$2
  for (k in aliases)
    delete aliases[k];
  $0=""
}

/^@alias/ {
  for (i=2; i<=NF; i++) {
    split($i, tok, "=");
    aliases[tok[1]] = tok[2];
  }
  $0=""
}

/^@long-alias-end/ && !long_alias_name {
  print(\
    FILENAME ":" NR ": " \
    "Long alias not started") > "/dev/stderr"
  err = 1;
  exit(1);
}

/^@long-alias-end/ {
  gsub(/  */, " ", long_alias_value);
  aliases[long_alias_name] = long_alias_value;
  $0 = long_alias_name = long_alias_value = "";
}

/^@long-alias/ {
  long_alias_name=$2;
  long_alias_value="";
  $0="";
}

/PRIVATE__/ {
  print(\
    FILENAME ":" NR ": " \
    "Used private variable without ~:\n\n" \
    "    " NR " > " $0) > "/dev/stderr"
  err = 1;
  exit(1);
}

/@(query|reachable|lemma)/ {
  if (match($0, /@(query|reachable|lemma)\s+"[^"]*"/) == 0) {
    print(\
      FILENAME ":" NR ": " \
      "@query or @reachable statement without parameter:\n\n" \
      "    " NR " > " $0) > "/dev/stderr"
    err = 1;
    exit(1);
  }
  pre   = substr($0, 1, RSTART-1);
  mat   = substr($0, RSTART, RLENGTh)
  post  = substr($0, RSTART+RLENGTH)

  gsub(/./, " ", mat);
  $0 = pre mat post;
}

function istok(c) {
  return c ~ /[0-9a-zA-Z_\']/;
}

{
  gsub("~", "PRIVATE__" module "__", $0);
}

{
  orig=$0;
  minibuf="";
  for (i=1; i<length($0); i+=1) {
    a=substr($0, i, 1); # previous character
    c=substr($0, i+1, 1); # this character
    if (i > 1 && istok(a)) continue; # We are inside a token
    if (!istok(c))         continue; # This is not the start of a token
    # ==> We are at a token boundary

    for (k in aliases) {
      t=substr($0, i+1, length(k)); # The potential token that equals the alias
      z=substr($0, i+length(k)+1, 1); # The char after the potential token
      if (t != k) continue; # Alias does not match
      if (istok(z)) continue; # Alias matches but is a prefix
      # ==> ALIAS MATCH

      val = aliases[k];
      prefix = substr($0, 0, i);
      suffix = substr($0, i+1+length(k));

      minibuf = minibuf prefix val;
      $0=suffix;
      i=1;
    }
  }
  $0 = minibuf $0;
}

long_alias_name {
  long_alias_value=long_alias_value $0 " ";
  $0=""
}

{
  buf=buf $0 "\n";
}

END {
  if (err == 0)
    print(buf)
}
