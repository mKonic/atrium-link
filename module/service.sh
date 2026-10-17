#!/system/bin/sh
# Runs the daemon as the shell user (the one allowed to read the clipboard
# in the background), restarting it if it dies.
MODDIR=${0%/*}
# The shell user's own directory: it can't reach /data/adb.
HOME_DIR=/data/user_de/0/com.android.shell/atrium-link
# Where the module kept its state when it was atrium-clipsync.
OLD_DIR=/data/user_de/0/com.android.shell/atrium-clipsync

(
    until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 2; done
    if [ -d "$OLD_DIR" ] && [ ! -d "$HOME_DIR" ]; then
        mv "$OLD_DIR" "$HOME_DIR"
        rm -f "$HOME_DIR/clipsync.dex" "$HOME_DIR/command" "$HOME_DIR/status.json"
    fi
    while [ ! -f "$MODDIR/remove" ]; do
        if [ -f "$MODDIR/disable" ]; then
            sleep 10
            continue
        fi
        mkdir -p "$HOME_DIR"
        # A new file, not over the old one: a running copy has that mapped.
        cp "$MODDIR/link.dex" "$HOME_DIR/link.dex.new"
        mv "$HOME_DIR/link.dex.new" "$HOME_DIR/link.dex"
        chown -R 2000:2000 "$HOME_DIR"
        chmod 700 "$HOME_DIR"
        chmod 600 "$HOME_DIR/link.dex"
        if [ -f "$HOME_DIR/log" ] && [ "$(stat -c %s "$HOME_DIR/log")" -gt 1048576 ]; then
            mv "$HOME_DIR/log" "$HOME_DIR/log.old"
        fi
        touch "$HOME_DIR/log"
        chmod 600 "$HOME_DIR/log"
        # The input group: the volume keys, when a PC has them (VolumeKeys).
        su 2000 -g 2000 -G 1004 -c "CLASSPATH=$HOME_DIR/link.dex exec app_process /system/bin dev.atrium.link.Main $HOME_DIR" \
            >> "$HOME_DIR/log" 2>&1
        # Another copy of this loop runs it already.
        [ $? = 3 ] && break
        sleep 5
    done
) &
