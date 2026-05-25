#!/bin/sh
# TODO-test: broker denies a cap not in policy; no fd is issued.
# Setup:  create X with empty policy; start X with broker-test, target=Y.
# Expect: agentd.log "broker denied cap=mailbox.send:Y to=X reason=not-in-caps";
#         X received no SCM_RIGHTS fd.
echo "TODO-test: broker_deny.sh — not implemented; see tests/README.md"
exit 1
