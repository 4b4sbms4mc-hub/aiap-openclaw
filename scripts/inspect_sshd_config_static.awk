# SPDX-License-Identifier: Apache-2.0
# Text inventory only: never resolve Include/Match or execute configuration.
BEGIN { print "PROFILE=x-aiap-sshd-static-inventory-v1"; print "SSH_CONFIG_SCOPE=static_text_not_effective_configuration" }
function uncomment(s,    i,c,quoted,escaped) {
    for (i=1; i<=length(s); i++) {
        c=substr(s,i,1)
        if (escaped) { escaped=0; continue }
        if (c=="\\") { escaped=1; continue }
        if (c=="\"") quoted=!quoted
        if (c=="#" && !quoted) return substr(s,1,i-1)
    }
    return s
}
NR>4096 { print "STATIC_STATUS=line_limit_reached"; exit }
length($0)>2048 { print "STATIC_SKIPPED=" NR " oversized_line"; next }
/-----BEGIN .*PRIVATE KEY-----/ { private_block=1; next }
private_block { if ($0~/-----END .*PRIVATE KEY-----/) private_block=0; next }
{
    line=uncomment($0)
    sub(/^[[:space:]]+/,"",line); sub(/[[:space:]]+$/,"",line)
    if (line=="") next
    control_check=line; gsub(/\t/,"",control_check)
    if (control_check~/[[:cntrl:]]/) { print "STATIC_SKIPPED=" NR " control_character"; next }
    key=line; sub(/[[:space:]=].*$/,"",key); key=tolower(key)
    value=substr(line,length(key)+1)
    sub(/^[[:space:]]*/,"",value); sub(/^=[[:space:]]*/,"",value)
    if (value=="") { print "STATIC_SKIPPED=" NR " missing_value"; next }
    if (key=="authorizedkeyscommand" || key=="forcecommand") {
        print "STATIC_SETTING=" NR " " key "_present " (tolower(value)=="none"?"no":"yes")
    } else if (key=="match") {
        print "STATIC_MATCH_BLOCK=" NR " present_not_evaluated"
    } else if (key=="include") {
        print "STATIC_INCLUDE=" NR " " value
    } else if (key~/^(pubkeyauthentication|authorizedkeysfile|strictmodes|authenticationmethods|permituserenvironment|usedns)$/) {
        print "STATIC_SETTING=" NR " " key " " value
    }
}
