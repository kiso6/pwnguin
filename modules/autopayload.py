metalist = [
    "windows/meterpreter/reverse_tcp",
    "java/meterpreter/reverse_tcp",
    "php/meterpreter/reverse_tcp",
    "php/meterpreter_reverse_tcp",
    "ruby/shell_reverse_tcp",
    "cmd/unix/interact",
    "cmd/unix/reverse",
    "cmd/unix/reverse_perl",
    "cmd/unix/reverse_netcat_gaping",
    "windows/meterpreter/reverse_nonx_tcp",
    "windows/meterpreter/reverse_ord_tcp",
    "windows/shell/reverse_tcp",
    "generic/shell_reverse_tcp",
]


def autochose(payloadlist):
    for meta in metalist:
        if meta in payloadlist:
            return meta
    return -1
