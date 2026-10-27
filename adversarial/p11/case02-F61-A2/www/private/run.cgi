#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'EXEC-PRIVATE uid='\n id -u\n uname -n\n