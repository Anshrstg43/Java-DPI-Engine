package com.dpi;

import java.util.ArrayList;
import java.util.List;

public class FPManager {
    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager, FastPathProcessor.PacketOutputCallback callback) {
        // Create the individual FastPathProcessor threads
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, callback));
        }
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) {
            fp.start();
        }
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) {
            fp.stop();
        }
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }
}