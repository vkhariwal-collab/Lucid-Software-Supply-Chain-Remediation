package com.lucid.warranty;

final class Check {
    static int failures = 0;

    static void that(boolean ok, String what) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + what);
        if (!ok) failures++;
    }

    static void exit() {
        System.exit(failures == 0 ? 0 : 1);
    }
}
