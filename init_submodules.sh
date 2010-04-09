#!/bin/sh
# This script removes files that get built in the agent source tree as part of
# the make process, but that should not be checked in and that should not 
# persist.
if [ -x ".git" ]; then
    echo "I appear to be running from the correct place.  Attempting to update"
    git submodule init
    git submodule update
    
    cd libsysshep
    git submodule init
    git submodule update

else
    echo "I can't find .git.  That means I'm probably not being run from the "
    echo "correct location (the agent project's top level source dir)"

fi