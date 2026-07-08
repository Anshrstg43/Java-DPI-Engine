package com.dpi;

import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

public class ThreadSafeQueue<T> {
    private final Queue<T> queue = new LinkedList<>();
    private final ReentrantLock mutex = new ReentrantLock();
    private final Condition notEmpty = mutex.newCondition();
    private final Condition notFull = mutex.newCondition();
    private final int maxSize;
    private boolean shutdown = false;

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    public void push(T item) throws InterruptedException {
        mutex.lockInterruptibly();
        try {
            while (queue.size() >= maxSize && !shutdown) {
                notFull.await(); // Sleep until queue has space
            }
            if (shutdown) return;
            queue.add(item);
            notEmpty.signal(); // Wake up a waiting consumer thread
        } finally {
            mutex.unlock();
        }
    }

    public boolean tryPush(T item) {
        mutex.lock();
        try {
            if (queue.size() >= maxSize || shutdown) {
                return false;
            }
            queue.add(item);
            notEmpty.signal();
            return true;
        } finally {
            mutex.unlock();
        }
    }

    public T pop() throws InterruptedException {
        mutex.lockInterruptibly();
        try {
            while (queue.isEmpty() && !shutdown) {
                notEmpty.await(); // Sleep until queue has a packet
            }
            if (queue.isEmpty()) return null;
            T item = queue.poll();
            notFull.signal(); // Wake up a waiting producer thread
            return item;
        } finally {
            mutex.unlock();
        }
    }

    public T popWithTimeout(long timeoutMillis) throws InterruptedException {
        mutex.lockInterruptibly();
        try {
            long nanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
            while (queue.isEmpty() && !shutdown) {
                if (nanos <= 0) return null;
                nanos = notEmpty.awaitNanos(nanos);
            }
            if (queue.isEmpty()) return null;
            T item = queue.poll();
            notFull.signal();
            return item;
        } finally {
            mutex.unlock();
        }
    }

    public boolean empty() {
        mutex.lock();
        try { return queue.isEmpty(); } finally { mutex.unlock(); }
    }

    public int size() {
        mutex.lock();
        try { return queue.size(); } finally { mutex.unlock(); }
    }

    public void shutdown() {
        mutex.lock();
        try {
            shutdown = true;
            notEmpty.signalAll(); // Wake up EVERYONE to exit cleanly
            notFull.signalAll();
        } finally {
            mutex.unlock();
        }
    }

    public boolean isShutdown() {
        mutex.lock();
        try { return shutdown; } finally { mutex.unlock(); }
    }
}