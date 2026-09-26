#include "timer.h"

IdleTimer::IdleTimer(std::chrono::milliseconds timeout, std::function<void()> callBack) :
    stopped(false),
    callBack(std::move(callBack)),
    timeout(timeout),
    lastActivity(std::chrono::steady_clock::now()),
    worker(&IdleTimer::run, this)
{ }

IdleTimer::~IdleTimer() {
    this->stop();
}

void IdleTimer::run() {
    std::unique_lock<std::mutex> guard(_mutex);

    while (!stopped) {
        cv.wait_for(guard, timeout);
        if (stopped) {
            return;
        }

        auto now = std::chrono::steady_clock::now();
        if (now - lastActivity > timeout) {
            guard.unlock();
            callBack();
            guard.lock();
            lastActivity = std::chrono::steady_clock::now();
        }
    }
}

void IdleTimer::stop() {
    {
        std::lock_guard<std::mutex> guard(_mutex);
        if (stopped)  {
            return;
        }
        stopped = true;
    }
    cv.notify_one();

    if (worker.joinable()) {
        worker.join();
    }
}

void IdleTimer::activity() {
    {
        std::lock_guard<std::mutex> guard(_mutex);
        if (stopped) {
            return;
        }
        lastActivity = std::chrono::steady_clock::now();
    }
    cv.notify_one();
}