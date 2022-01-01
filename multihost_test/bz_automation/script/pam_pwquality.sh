# $1 - user
# $2 - current passwd
# $3 - new passwd
# $4 - new retry passwd
set_passwd() {
    expect -c "
        # exp_internal 1
        set timeout 20
        #puts {step 1}
        if { {$1} eq {root} } {
            spawn passwd
            expect_after {
              timeout {puts TIMEOUT; exit 10}
              eof {puts EOF; exit 11}
            }
        } else {
            spawn su - -c 'passwd' $1
            expect_after {
              timeout {puts TIMEOUT; exit 10}
              eof {puts EOF; exit 6}
            }
            expect {
                -nocase {current*} { puts $2; send -- $2\r }
                -nocase {error} { exit 3 }
            }
        }
        #puts {step 2}
        expect {
            -nocase {new*} { puts $3; send -- $3\r }
        }
        #puts {step 3}
        expect {
            -nocase {retype*} { puts $4; send -- $4\r }
            -nocase {similar} { exit 4 }
            -nocase -re {bad password.*monotonic} { exit 7 }
            -nocase -re {bad password.*too short} { exit 8 }
            -nocase {bad password} { exit 5 }
        }
        #puts {step 4}
        expect {
            -nocase {new} { exit 1 }
            -nocase {preliminary} { exit 2 }
            -nocase {do not match} {
                #puts {step 5}
                expect {
                    eof { exit 6 }
                    -nocase {new} { exit 1 }
                }
	    }
            -nocase {successfully} { exit 0 }
        }
    "
}

set_passwd $1 $2 $3 $4
