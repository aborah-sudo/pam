            expect -f  - <<<'
            set timeout 5
            spawn ssh -o StrictHostKeyChecking=no -l local_anuj localhost
            expect "*password:"
            send -- "password1234\r"
            expect "*$ "
            expect eof
        '

