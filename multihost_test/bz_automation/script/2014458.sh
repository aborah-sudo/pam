            expect -f  - <<<'
            set timeout 5
            spawn ssh -o StrictHostKeyChecking=no -l local_anuj localhost
            expect "*password:"
            send -- "password123\r"
            expect "*$ "
            expect eof
        '

