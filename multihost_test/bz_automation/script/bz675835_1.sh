          expect <<EOF
            spawn -noecho passwd local_anuj
            set timeout 5
            expect {
              timeout {exit 1}
              eof {exit 1}
              -nocase "new*password" { puts x; send -- "x\r"}
            }
            expect {
              timeout {exit 1}
              eof {exit 1}
              -nocase "retype*password" { puts x; send -- "x\r"}
            }
            expect eof
EOF
          expect <<EOF
            spawn -noecho passwd pamtest1
            set timeout 5
            expect {
              timeout {exit 1}
              eof {exit 1}
              -nocase "new*password" { puts x; send -- "x\r"}
            }
            expect {
              timeout {exit 1}
              eof {exit 1}
              -nocase "retype*password" { puts x; send -- "x\r"}
            }
            expect eof
EOF
