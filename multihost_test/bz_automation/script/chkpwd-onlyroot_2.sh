CMD_CHKPWD=${CMD:-"/sbin/unix_chkpwd"}

testchkpwd() {
RUSERNAME=$1
USERNAME=$2
PASSWORD=$3
echo -n "$RUSERNAME checking password for $USERNAME "
su - $RUSERNAME -c "echo -n -e \"$PASSWORD\\0000\" | $CMD_CHKPWD $USERNAME nullok"
}

testchkpwd $1 $2 $3