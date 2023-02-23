#!/bin/sh
# Copyright 2015 Brent Longborough
# modified 2023 by Marei Peischl
# Part of gitinfo2 package Version 2
# Release 2.0.7 2015-11-22
# Please read gitinfo2.pdf for licencing and other details
# -----------------------------------------------------
# Post-{commit,checkout,merge} hook for the gitinfo2 package
#
# Get the first tag found in the history from the current HEAD
FIRSTTAG=$(git describe --tags --always --dirty='-*' 2>/dev/null)
# Get the first tag in history that looks like a Release
RELTAG=$(git describe --tags --long --always --dirty='-*' --match '[0-9]*.*' 2>/dev/null)
# Hoover up the metadata
git --no-pager log -1 --date=short --decorate=short \
    --pretty=format:"\usepackage[%
        shash={%h},
        lhash={%H},
        authname={%an},
        authemail={%ae},
        authsdate={%ad},
        authidate={%ai},
        authudate={%at},
        commname={%cn},
        commemail={%ce},
        commsdate={%cd},
        commidate={%ci},
        commudate={%ct},
        refnames={%d},
        firsttagdescribe={$FIRSTTAG},
        reltag={$RELTAG}
    ]{gitexinfo}" HEAD > gitHeadInfo.gin
