#pragma once

#include <chrono>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <functional>

class IdleTimer {
    private:
        bool stopped;
        std::function<void()> callBack;
        
        std::chrono::milliseconds timeout;
        std::chrono::time_point<std::chrono::steady_clock> lastActivity;
        
        std::thread worker;
        std::mutex _mutex;
        std::condition_variable cv;

    private:
        void run();
    
    public:
        IdleTimer(std::chrono::milliseconds, std::function<void()>);
        ~IdleTimer();

        void activity();
        void stop();
};