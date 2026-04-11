/run/credman/credman.sock     root:credman 660
                              any user in 'credman' group can connect

Credential namespace:
  credman-<uid>-<name>        per-user isolation in same credstore
  e.g. credman-1000-openai-key (kk)
       credman-1001-openai-key (another user)

Audit log → systemd journal:
  CREDMAN_OP=set
  CREDMAN_NAME=OPENAI_KEY
  CREDMAN_UID=1000
  CREDMAN_USER=kk
  CREDMAN_RESULT=ok
  (never logs VALUE)
