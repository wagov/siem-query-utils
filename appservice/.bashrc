# Import our environment variables from docker launch
if [[ -n $SSH_CONNECTION ]] ; then
    for e in $(tr "\000" "\n" < /proc/1/environ); do
        eval "export $e"
    done
fi
