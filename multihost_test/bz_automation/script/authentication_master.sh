function do_ssh_from_master {
    expect -f  - <<-EOF
        set timeout 5
        spawn ssh -o StrictHostKeyChecking=no -l local_anuj $1
        expect "*password:"
        send -- "password123\r"
        expect eof
EOF
}


do_ssh_from_master $1
