#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'EXEC-PUBLIC uid='\n id -u\n uname -n\n