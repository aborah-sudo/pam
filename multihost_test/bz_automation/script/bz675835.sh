# $1 user
# $2 pass

host=localhost

function do_ssh {
expect <<EOF
set timeout 10
spawn ssh $1@${host}
expect_after {
  timeout {puts TIMEOUT; exit 4}
  eof {puts EOF; exit 1}
}
expect {
  "yes/no" {send "yes\r"; exp_continue}
  "assword:" { send "$2\r" }
}
expect {
  "assword:" { exit 3 }
  {\\\$} {send "whoami\r"}
}
expect "$1" { expect {\\\$} {send "exit\r"} }
expect eof
EOF
}

do_ssh $1 $2