setpass() {
USERNAME=$1
PASSWORD=$2
# sets password
expect -f - << EOF
log_user 0
spawn -noecho passwd $USERNAME
expect "assword:"
send -- "$PASSWORD\r"
expect "assword:"
send -- "$PASSWORD\r"
expect eof
EOF
}

setpass $1 $2