#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

source "$(dirname "$0")/_common.sh"

# If not root, exit
if [ "$(id -u)" -ne 0 ]; then
    fatal "Requires running as root"
fi

# Parse arguments
REMOVE_UTUN=0
UTUN_DEV="utun99"
UTUN_IP="10.0.0.1"
while getopts ":hdt:i:" opt; do
    case $opt in
        h)
            echo "Usage: $0 [-h] [-d] [-t UTUN] [-i IP]" 1>&2
            echo "  -h  Show this help message" 1>&2
            echo "  -d  Remove the utun device IP configuration" 1>&2
            echo "  -t  utun device name (default: $UTUN_DEV)" 1>&2
            echo "  -i  utun IP address (default: $UTUN_IP)" 1>&2
            exit 0
            ;;
        d)
            REMOVE_UTUN=1
            ;;
        t)
            UTUN_DEV="$OPTARG"
            ;;
        i)
            UTUN_IP="$OPTARG"
            ;;
        :)
            fatal "Option -$OPTARG requires an argument"
            ;;
        \?)
            fatal "Invalid option: -$OPTARG"
            ;;
    esac
done

check_for_tools ifconfig

info "Script parameters:"
info2 "utun device: ${BOLD}${UTUN_DEV}${RESET}"
if [ $REMOVE_UTUN -eq 1 ]; then
    info2 "Remove utun configuration: ${BOLD}yes${RESET}"
else
    info2 "utun IP: ${BOLD}${UTUN_IP}/24${RESET}"
fi

# Check if the utun device exists
if ! ifconfig "$UTUN_DEV" &> /dev/null; then
    if [ $REMOVE_UTUN -eq 1 ]; then
        warn "utun device ${BOLD}${UTUN_DEV}${RESET} does not exist"
        fatal "Nothing to remove"
    fi
    fatal "utun device ${BOLD}${UTUN_DEV}${RESET} does not exist. The device must be created first (e.g., by the litebox runner)."
fi

if [ $REMOVE_UTUN -eq 1 ]; then
    info "Removing IP configuration from ${UTUN_DEV}"
    ifconfig "$UTUN_DEV" delete "$UTUN_IP" 2>/dev/null || true
    success "Removed utun configuration"
    exit 0
fi

info "Assigning IP address ${UTUN_IP}/24 to ${UTUN_DEV}"
ifconfig "$UTUN_DEV" "$UTUN_IP" "$UTUN_IP" netmask 255.255.255.0 up

# Add route to the guest subnet
info "Adding route to 10.0.0.0/24 via ${UTUN_DEV}"
route -n add -net 10.0.0.0/24 -interface "$UTUN_DEV" 2>/dev/null || true

success "Configured utun device ${UTUN_DEV} with IP ${UTUN_IP}/24"
